rule CyberShield_Proxy_Environment_Manipulation
{
    meta:
        description = "Injects proxy or certificate settings into the victim's trust store"
        author = "CyberShield"
        severity = "high"
        category = "man-in-the-middle"
    strings:
        $trust = /(certutil(\.exe)?\s+(-addstore|-addagent|-addroot)|\bCert:\\\\|\\bRoot\\b\\s*certificatestore|certutil\s+-generateSSTFromWURoots)/ nocase
        $reg   = /(HK(LM|CU)\\SOFTWARE\\Microsoft\\System\\CurrentVersion\\Internet Settings|HKEY_(LOCAL|CURRENT)_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings)/ nocase
        $proxy = /(ProxyEnable|ProxyServer|AutoConfigURL|WinHttpSetProxySetting|setx\s+http_proxy)/ nocase
        $host  = /(cert|bundle|pem|crt)\b.*https?:\/\/[^\s"']+/ nocase
    condition:
        ($trust and $host) or ($reg and $proxy)
}

rule CyberShield_Ransom_Note_Text
{
    meta:
        description = "Ransom-note language demanding payment for decryption"
        author = "CyberShield"
        severity = "critical"
        category = "ransomware"
        authoritative = "true"
    strings:
        $a = /(your\s+files\s+(have\s+been|were|are)\s+encrypted|all\s+your\s+(important\s+)?files\s+(are|have\s+been)\s+encrypted)/ nocase
        $b = /(to\s+decrypt\s+your\s+files|decryption\s+key|pay\s+the\s+ransom|ransom\s+(amount|fee)|your\s+personal\s+decryption\s+key)/ nocase
        $c = /(bitcoin|monero|btc|wallet\s+address|crypto\s+wallet|payment\s+address)/ nocase
        $d = /(double\s+your\s+(ransom|price)|price\s+will\s+(double|be\s+doubled)|permanently\s+(deleted|lost)|do\s+not\s+(rename|modify|edit))/ nocase
        $e = /(contact\s+(us|me)\s+(at|via)|telegram|@protonmail\.com|onion)/ nocase
        $time = /(\d{1,3}\s*(hours|hrs|days)\b.*?(deadline|expire|deleted)|deadline[:\s]|permanent\s+loss)/ nocase
    condition:
        ($a or $b) and 1 of ($c, $d, $e, $time)
}

rule CyberShield_Banking_Trojan_Web_Inject
{
    meta:
        description = "Web-inject configuration targeting online banking or crypto exchanges"
        author = "CyberShield"
        severity = "critical"
        category = "financial-theft"
        authoritative = "true"
    strings:
        $inject = /(webinject|web_inject|inject\.rul|inject\.txt|grabber|formgrab|man\b.*in\b.*the.*middle|mitm.*inject)/ nocase
        $target = /(\/\*\*?\/@match\s*:\s*\*:\/\/[^ ]*\.(com|net|org|ru|ua|pl|cn|co\.uk)|banking|bank|wallet|exchange|binance|coinbase|metamask|blockchain)/ nocase
        $grab   = /(querySelector(All)?\s*\(\s*["'][^"']*(passw|pin|cvv|card|otp|token|secret))|(document\.(querySelector|getElementById)\s*\(\s*["'][^"']*(passw|login|user|otp))|(["']grab["']\s*:)|(\.grab\s*=)/ nocase
        $send   = /(XMLHttpRequest|fetch\s*\(|sendBeacon|FormData|\.submit\s*\()|("[a-z_]*(send|post|exfil|upload|uploadurl)[a-z_]*"\s*:)/ nocase
    condition:
        $inject and ($target or $grab) and ($grab or $send)
}

rule CyberShield_Anti_Analysis_Evasion
{
    meta:
        description = "Environment checks that indicate anti-analysis or anti-VM behaviour"
        author = "CyberShield"
        severity = "low"
        category = "evasion"
    strings:
        $vm1 = /(VMware|VirtualBox|VBOX|QEMU|Xen|Hyper-V|SbieDll|wine_get_unix_file_name|Sandboxie)/ nocase
        $vm2 = /(\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\ControlSet001\\\\Services\\\\|vmtoolsd|vmwaretray|vboxservice|vmacthlp)/ nocase
        $dbg = /(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ProcessDebugPort|ProcessDebugFlags|OutputDebugStringA)/ nocase
        $time = /(rdtsc|GetTickCount\s*\(\s*\)|QueryPerformanceCounter|int\s+0x2d)/ nocase
        $sandbox = /(c:\\\\users\\\\.*\\\\appdata|\\\\sample\\.malware|malware|sandbox|analysis|cuckoo|\/tmp\/.*sample)/ nocase
        $sleep = /(Sleep\s*\(\s*\d{5,}|Start-Sleep\s+-Seconds\s+\d{2,}|time\.sleep\s*\(\s*\d{4,})/ nocase
    condition:
        2 of ($vm1, $vm2, $dbg, $time, $sandbox, $sleep)
}

rule CyberShield_C2_Beacon_Staging_Tunnel
{
    meta:
        description = "References a tunnelling or request-capture service commonly used for C2 and exfiltration"
        author = "CyberShield"
        severity = "high"
        category = "command-and-control"
    strings:
        $tunnel = /(ngrok\.io|ngrok-free\.app|trycloudflare\.com|loca\.lt|serveo\.net|localtunnel\.me|pagekite|updog\.dev)/ nocase
        $collaborator = /(burpcollaborator\.net|oastify\.com|interact\.sh|requestbin|webhook\.site|pipedream\.net|beeceptor\.com|dnslog\.cn|\.oast\.)/ nocase
        $paste = /(pastebin\.com|paste\.ee|rentry\.co|hastebin\.com|dpaste\.\w+|ix\.io|termbin\.com|controlc\.com)/ nocase
        $short = /(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|shorturl\.at|rebrand\.ly|t\.ly|rb\.gy|x\.co|ow\.ly)/ nocase
        $use  = /(curl\s+[^\n]{0,120}|wget\s+[^\n]{0,120}|Invoke-WebRequest|DownloadString|urlopen|requests\.(get|post)|fetch\s*\()/ nocase
    condition:
        (1 of ($tunnel, $collaborator, $paste, $short)) and $use
}

rule CyberShield_Crypto_Miner_Configuration
{
    meta:
        description = "Mining-pool configuration and wallet embedded in a sample"
        author = "CyberShield"
        severity = "high"
        category = "resource-abuse"
    strings:
        $miner = /(stratum\+(tcp|ssl):\/\/|xmrig|cpuminer|cgminer|ethminer|nbminer|phoenixminer|lolminer|minerd)/ nocase
        $algo  = /("algo"\s*:\s*"(randomx|cryptonight|cn2|ethash|kawpow|equihash|argon2)"|--algo=\s*(randomx|cryptonight|cn2|ethash|kawpow))/ nocase
        $pool  = /(pool\.(minexmr|supportxmr|f2pool|nanopool|supportmonero|hashvault)\.(com|org)|"pool"\s*:\s*"[^"]+:\s*(3333|4444|5555|14444|45700)\b)/ nocase
        $wallet = /([13][a-km-zA-HJ-NP-Z1-9]{25,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|8[1-9A-HJ-NP-Za-km-z]{40,})/ nocase
        $flag  = /(--user\s+[13][a-km-zA-HJ-NP-Z1-9]{25,34}|--donate-level|--coin\s+monero)/ nocase
    condition:
        $miner and 1 of ($algo, $pool, $wallet, $flag)
}