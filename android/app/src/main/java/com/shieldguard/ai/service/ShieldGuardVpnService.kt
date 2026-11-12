package com.shieldguard.ai.service

import android.app.Notification
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.shieldguard.ai.ShieldGuardApp
import com.shieldguard.ai.data.local.EncryptedPreferencesManager
import com.shieldguard.ai.domain.model.ModuleType
import com.shieldguard.ai.domain.model.Threat
import com.shieldguard.ai.domain.model.ThreatLevel
import com.shieldguard.ai.domain.model.Verdict
import com.shieldguard.ai.domain.repository.ThreatRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.UUID
import javax.inject.Inject

@AndroidEntryPoint
class ShieldGuardVpnService : VpnService() {

    @Inject
    lateinit var networkTrafficMonitor: NetworkTrafficMonitor

    @Inject
    lateinit var threatRepository: ThreatRepository

    @Inject
    lateinit var preferencesManager: EncryptedPreferencesManager

    private var vpnInterface: ParcelFileDescriptor? = null
    private val vpnScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnelJob: Job? = null
    private var auditJob: Job? = null

    @Volatile
    private var isRunning = false

    private val highRiskPorts = setOf(4444, 1337, 31337, 6667, 5555, 9001, 8443)

    companion object {
        const val ACTION_START = "com.shieldguard.ai.VPN_START"
        const val ACTION_STOP = "com.shieldguard.ai.VPN_STOP"
        const val ACTION_RELOAD = "com.shieldguard.ai.VPN_RELOAD"

        private const val VPN_ADDRESS = "10.10.0.2"
        private const val VPN_DNS_LOCAL = "10.10.0.1"
        private const val UPSTREAM_DNS_PRIMARY = "1.1.1.2"
        private const val UPSTREAM_DNS_SECONDARY = "9.9.9.9"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                restartTunnel()
                return START_STICKY
            }
        }

        if (isRunning) return START_STICKY

        startForeground(1001, createStatusNotification())
        startVpnTunnel()
        startNetworkAuditor()
        return START_STICKY
    }

    private fun restartTunnel() {
        tunnelJob?.cancel()
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        if (isRunning) {
            startVpnTunnel()
        }
    }

    private fun startVpnTunnel() {
        tunnelJob = vpnScope.launch {
            try {
                val builder = Builder()
                    .setSession("ShieldGuard Network Firewall")
                    .addAddress(VPN_ADDRESS, 32)
                    // Intercept all DNS queries at 10.10.0.1
                    .addDnsServer(VPN_DNS_LOCAL)
                    .addRoute(VPN_DNS_LOCAL, 32)
                    .setMtu(1500)
                    .setBlocking(true)

                // Bypass ShieldGuard's own socket traffic to avoid routing loops
                runCatching { builder.addDisallowedApplication(packageName) }

                // Sinkhole all known unauthorized & user-blocked IPs (blocks incoming & outgoing)
                for (blockedIp in networkTrafficMonitor.getAllBlockedIps()) {
                    runCatching { builder.addRoute(blockedIp, 32) }
                }

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    stopVpn()
                    return@launch
                }

                isRunning = true
                preferencesManager.setVpnProtectionEnabled(true)
                networkTrafficMonitor.setVpnRunning(true)

                vpnInterface?.let { pfd ->
                    val inStream = FileInputStream(pfd.fileDescriptor)
                    val outStream = FileOutputStream(pfd.fileDescriptor)
                    val packetBuf = ByteArray(32767)

                    while (isActive && isRunning) {
                        val length = inStream.read(packetBuf)
                        if (length <= 0) continue

                        handleOutboundIpPacket(packetBuf, length, outStream)
                    }
                }
            } catch (e: Exception) {
                // Socket / PFD closed during teardown or reload
            }
        }
    }

    private fun handleOutboundIpPacket(packet: ByteArray, length: Int, outStream: FileOutputStream) {
        if (length < 20) return
        val version = (packet[0].toInt() shr 4) and 0x0F
        if (version != 4) return

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl) return

        val protocol = packet[9].toInt() and 0xFF
        val dstIp = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

        // 1. Check if destination IP is in unauthorized IP sinkhole
        if (dstIp != VPN_DNS_LOCAL && networkTrafficMonitor.getAllBlockedIps().contains(dstIp)) {
            logAndRecordBlock(
                destination = dstIp,
                direction = "OUTBOUND/INBOUND",
                protocol = if (protocol == 6) "TCP" else "UDP",
                reason = "Blocked unauthorized remote IP address"
            )
            // Packet is dropped intentionally
            return
        }

        // 2. Intercept DNS queries (UDP protocol 17, destination port 53 to VPN_DNS_LOCAL)
        if (protocol == 17 && length >= ihl + 8) {
            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
            if (dstPort == 53) {
                val dnsOffset = ihl + 8
                val dnsLength = length - dnsOffset
                if (dnsLength > 12) {
                    val domain = extractDnsDomainName(packet, dnsOffset, dnsLength)
                    val packetCopy = packet.copyOf(length)
                    vpnScope.launch {
                        processDnsQuery(packetCopy, ihl, dnsOffset, dnsLength, domain, outStream)
                    }
                    return
                }
            }
        }
    }

    private suspend fun processDnsQuery(
        requestPacket: ByteArray,
        ihl: Int,
        dnsOffset: Int,
        dnsLength: Int,
        domain: String,
        outStream: FileOutputStream
    ) {
        val (isBlocked, reason) = networkTrafficMonitor.evaluateDomain(domain)

        if (isBlocked) {
            logAndRecordBlock(
                destination = domain,
                direction = "OUTBOUND",
                protocol = "DNS",
                reason = reason
            )
            val nxDomainDns = buildDnsNxDomainResponse(requestPacket, dnsOffset, dnsLength)
            if (nxDomainDns != null) {
                val responseIpPacket = buildUdpIpResponse(requestPacket, ihl, nxDomainDns)
                synchronized(outStream) {
                    runCatching { outStream.write(responseIpPacket) }
                }
            }
            return
        }

        // Authorized domain: forward query over protected UDP socket
        networkTrafficMonitor.recordEvent(
            NetworkTrafficEvent(
                id = UUID.randomUUID().toString(),
                destination = domain,
                direction = "OUTBOUND",
                protocol = "DNS",
                status = "ALLOWED",
                reason = reason,
                timestampMs = System.currentTimeMillis()
            )
        )

        val dnsQueryBytes = requestPacket.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val dnsAnswer = forwardDnsOverProtectedSocket(dnsQueryBytes, UPSTREAM_DNS_PRIMARY)
            ?: forwardDnsOverProtectedSocket(dnsQueryBytes, UPSTREAM_DNS_SECONDARY)

        if (dnsAnswer != null) {
            val responseIpPacket = buildUdpIpResponse(requestPacket, ihl, dnsAnswer)
            synchronized(outStream) {
                runCatching { outStream.write(responseIpPacket) }
            }
        }
    }

    private fun forwardDnsOverProtectedSocket(query: ByteArray, dnsServer: String): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 3000
            val address = InetAddress.getByName(dnsServer)
            val outPacket = DatagramPacket(query, query.size, address, 53)
            socket.send(outPacket)

            val recvBuf = ByteArray(4096)
            val inPacket = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(inPacket)
            recvBuf.copyOf(inPacket.length)
        } catch (_: Exception) {
            null
        } finally {
            runCatching { socket?.close() }
        }
    }

    private fun startNetworkAuditor() {
        auditJob?.cancel()
        auditJob = vpnScope.launch {
            while (isActive && isRunning) {
                inspectActiveNetworkPosture()
                inspectActiveSockets()
                delay(4000)
            }
        }
    }

    private fun inspectActiveNetworkPosture() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            val network = cm.activeNetwork ?: return
            val caps = cm.getNetworkCapabilities(network) ?: return

            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) {
                networkTrafficMonitor.setNetworkWarning("Captive portal / Public WiFi detected — Firewall filtering active")
            } else if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                networkTrafficMonitor.setNetworkWarning("Unvalidated network connection — Inspecting DNS & routes")
            } else {
                networkTrafficMonitor.setNetworkWarning(null)
            }
        } catch (_: Exception) {
            // Ignored
        }
    }

    private fun inspectActiveSockets() {
        // Inspect /proc/net/tcp and /proc/net/tcp6 when permitted by SELinux policy
        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { procPath ->
            try {
                val file = File(procPath)
                if (!file.exists() || !file.canRead()) return@forEach
                val lines = file.readLines().drop(1)
                for (line in lines) {
                    val cols = line.trim().split(Regex("\\s+"))
                    if (cols.size < 4) continue
                    val localAddr = cols[1]
                    val remAddr = cols[2]
                    val stateHex = cols[3]

                    val remPort = remAddr.substringAfter(':').toIntOrNull(16) ?: 0
                    val localPort = localAddr.substringAfter(':').toIntOrNull(16) ?: 0

                    // State 0A = LISTEN (Incoming listening socket), 01 = ESTABLISHED
                    if (stateHex == "0A" && localPort in highRiskPorts) {
                        logAndRecordBlock(
                            destination = "Local Port :$localPort",
                            direction = "INBOUND_LISTEN",
                            protocol = "TCP",
                            reason = "Unauthorized high-risk incoming listener port ($localPort)"
                        )
                    } else if (stateHex == "01" && remPort in highRiskPorts) {
                        logAndRecordBlock(
                            destination = "Remote Port :$remPort",
                            direction = "OUTBOUND",
                            protocol = "TCP",
                            reason = "Suspicious outbound C2 port connection ($remPort)"
                        )
                    }
                }
            } catch (_: Exception) {
                // Non-root / Android 10+ SELinux restricts /proc/net/tcp
            }
        }
    }

    private fun logAndRecordBlock(
        destination: String,
        direction: String,
        protocol: String,
        reason: String
    ) {
        networkTrafficMonitor.recordEvent(
            NetworkTrafficEvent(
                id = UUID.randomUUID().toString(),
                destination = destination,
                direction = direction,
                protocol = protocol,
                status = "BLOCKED",
                reason = reason,
                timestampMs = System.currentTimeMillis()
            )
        )

        vpnScope.launch {
            threatRepository.recordThreat(
                Threat(
                    id = UUID.randomUUID().toString(),
                    moduleType = ModuleType.NETWORK,
                    threatLevel = ThreatLevel.HIGH,
                    verdict = Verdict.MALICIOUS,
                    riskScore = 85,
                    title = "Blocked $direction Traffic: $destination",
                    description = reason,
                    actionTaken = "BLOCKED",
                    rawPayload = destination,
                    indicators = listOf("Protocol: $protocol", "Direction: $direction", reason),
                    timestampMs = System.currentTimeMillis()
                )
            )
        }
    }

    private fun extractDnsDomainName(packet: ByteArray, dnsOffset: Int, dnsLength: Int): String {
        val sb = StringBuilder()
        var pos = dnsOffset + 12 // Skip 12-byte DNS header
        val end = dnsOffset + dnsLength
        while (pos < end) {
            val labelLen = packet[pos].toInt() and 0xFF
            if (labelLen == 0) break
            if ((labelLen and 0xC0) == 0xC0 || pos + 1 + labelLen > end) break
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..labelLen) {
                sb.append(packet[pos + i].toInt().toChar())
            }
            pos += 1 + labelLen
        }
        return sb.toString()
    }

    private fun buildDnsNxDomainResponse(packet: ByteArray, dnsOffset: Int, dnsLength: Int): ByteArray? {
        if (dnsLength < 12) return null
        val resp = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        // Set QR = 1 (Response), RD preserved, RA = 1, RCODE = 3 (NXDOMAIN)
        resp[2] = ((resp[2].toInt() and 0x01) or 0x81).toByte()
        resp[3] = 0x83.toByte() // RA=1, RCODE=3 (Name Error / Blocked)
        // Zero ANCOUNT, NSCOUNT, ARCOUNT
        resp[6] = 0; resp[7] = 0
        resp[8] = 0; resp[9] = 0
        resp[10] = 0; resp[11] = 0
        return resp
    }

    private fun buildUdpIpResponse(requestPacket: ByteArray, ihl: Int, dnsPayload: ByteArray): ByteArray {
        val totalLen = ihl + 8 + dnsPayload.size
        val resp = ByteArray(totalLen)
        // Copy original IP header
        System.arraycopy(requestPacket, 0, resp, 0, ihl)

        // Total Length
        resp[2] = ((totalLen shr 8) and 0xFF).toByte()
        resp[3] = (totalLen and 0xFF).toByte()

        // Swap Source IP (bytes 12..15) and Destination IP (bytes 16..19)
        System.arraycopy(requestPacket, 16, resp, 12, 4)
        System.arraycopy(requestPacket, 12, resp, 16, 4)

        // Compute IPv4 header checksum
        resp[10] = 0
        resp[11] = 0
        val ipChecksum = computeChecksum(resp, 0, ihl)
        resp[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        resp[11] = (ipChecksum and 0xFF).toByte()

        // Swap UDP SrcPort and DstPort
        resp[ihl] = requestPacket[ihl + 2]
        resp[ihl + 1] = requestPacket[ihl + 3]
        resp[ihl + 2] = requestPacket[ihl]
        resp[ihl + 3] = requestPacket[ihl + 1]

        // UDP Length
        val udpLen = 8 + dnsPayload.size
        resp[ihl + 4] = ((udpLen shr 8) and 0xFF).toByte()
        resp[ihl + 5] = (udpLen and 0xFF).toByte()

        // UDP Checksum = 0 (optional for IPv4)
        resp[ihl + 6] = 0
        resp[ihl + 7] = 0

        // DNS Payload
        System.arraycopy(dnsPayload, 0, resp, ihl + 8, dnsPayload.size)
        return resp
    }

    private fun computeChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length) {
            val high = (buf[i].toInt() and 0xFF) shl 8
            val low = if (i + 1 < offset + length) (buf[i + 1].toInt() and 0xFF) else 0
            sum += high or low
            if ((sum and 0xFFFF0000.toInt()) != 0) {
                sum = (sum and 0xFFFF) + (sum ushr 16)
            }
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun createStatusNotification(): Notification {
        return NotificationCompat.Builder(this, ShieldGuardApp.CHANNEL_MONITOR_STATUS)
            .setContentTitle("ShieldGuard Network Firewall Active")
            .setContentText("Scanning incoming & outgoing traffic; blocking unauthorized hosts.")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .build()
    }

    private fun stopVpn() {
        isRunning = false
        tunnelJob?.cancel()
        auditJob?.cancel()
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        preferencesManager.setVpnProtectionEnabled(false)
        networkTrafficMonitor.setVpnRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        vpnScope.cancel()
    }
}
