# Platform Capability Matrix

| Feature | Android | iOS | Windows | macOS | Linux | Notes |
|---|---|---|---|---|---|---|
| URL/Phishing Protection | Partial (VPN/App) | Partial (Network Extension) | Yes | Partial | Yes (agent+ext) | OS restrictions apply |
| File Scanning | SAF-limited | Sandbox-limited | Yes | Partial | Yes (clamscan) | Full disk access varies |
| APK Scanning | Yes (static) | N/A | N/A | N/A | N/A | Android only |
| Permission Monitor | Yes (API) | Limited | Partial | Limited | Limited | Respect privacy |
| Network Monitoring/DNS | VPN API | Network Extension | WFP/Firewall | PF/Firewall | iptables/nftables/Suricata | Filtering needs perms |
| Ransomware Behavior | Limited | Limited | Partial | Partial | Partial (inotify/fanotify) | Heuristics |
| USB/External Devices | Limited | N/A | Yes | Partial | udev rules | Desktop only |
| Browser Extensions | N/A | Limited | Yes | Yes | Yes | MV3 support varies |
| Email Security (OAuth) | Yes | Yes | Yes | Yes | Yes | API-based only |

**Note:** If unavailable, closest supported alternative provided with explanation.
