# CyberShield Platform Capability Matrix

CyberShield enforces modularity so each platform utilizes its maximum supported security capabilities without violating operating-system sandboxes or application store review guidelines.

| Security Module | Android (Kotlin) | iOS (Swift) | Windows (Rust/C#) | macOS (Swift/Rust) | Linux (Rust) | Browser Ext (TS) |
|---|---|---|---|---|---|---|
| **Module A: URL & Phishing** | Supported (VpnService / Accessibility) | Supported (NetworkExtension) | Supported (Winsock / WFP) | Supported (NetworkExtension) | Supported (iptables / nftables) | Supported (webNavigation / contentScript) |
| **Module B: Full File Scan** | App sandbox + Shared Media only | App sandbox only | Full File System (NTFS) | Full Disk Access (User Entitlement) | Full File System (ext4/btrfs) | Download pre-scan only |
| **Module C: APK Scanner** | Supported (PackageManager / SAX Parser) | Remote cloud inspection only | Remote / Desktop CLI analysis | Remote / Desktop CLI analysis | Native Python/CLI inspection | N/A |
| **Module D: Permission Monitor** | Supported (AppOpsManager / Settings API) | In-App Privacy Indicators | N/A (Admin ACL checks) | TCC Database Inspection (FDA) | Linux DAC / Capabilities | Extension Permission Assessor |
| **Module E: Network Shield** | VpnService Local Loopback | NEFilterDataProvider | Windows Filtering Platform (WFP) | NetworkExtension Content Filter | eBPF / iptables / Suricata | declarativeNetRequest |
| **Module F: Browser Security** | WebView & Default Browser intents | Safari Web Extension | Chrome, Edge, Firefox, Brave | Safari, Chrome, Firefox | Chrome, Firefox | Native WebExtension Manifest V3 |
| **Module G: Email Security** | IMAP/OAuth 2.0 Client API | IMAP/OAuth 2.0 Client API | Outlook MAPI / Graph API | Mail.app plugin / Graph API | Headless IMAP / OAuth 2.0 | Webmail DOM Scanner |
| **Module H: Ransomware Shield** | Scoped Storage change notification | Not supported by OS sandbox | File System Minifilter driver | Endpoint Security framework (ESF) | inotify / fanotify tripwires | N/A |
| **Module I: Download Protection** | DownloadManager broadcast receiver | DocumentPicker / Share Sheet | Shell Execution Hooks / MOTW | Quarantine Extended Attributes | inotify on ~/Downloads | Downloads API onCreated |
| **Module J: Vulnerability Scan** | Security Patch Level / Package Manager | iOS Version baseline check | Windows Update API / Registry | SoftwareUpdate / Homebrew audit | dpkg / rpm / listening ports | Extension security posture |
| **Module K: USB & External Device** | USB Host Intent / OTG storage scan | MFi storage picker only | USBOBLIVION / Device Notification | IOKit USB notifications | udev rules / /dev/disk watcher | N/A |
| **Module L: AI Threat Engine** | ONNX Runtime Mobile / Cloud API | CoreML / Cloud API | ONNX Runtime / Local Models | CoreML / ONNX Runtime | Local Scikit-learn / ONNX Engine | Lightweight regex & API |

### Operating System Restrictions & Safety Boundaries
1. **Android**: Does not utilize Accessibility services for covert spyware, keystroke interception, or unauthorized private message collection. Direct deep OS permission revoking must route the user to standard system `ACTION_APPLICATION_DETAILS_SETTINGS`.
2. **iOS**: Apple strict app sandboxing prevents cross-application scanning or direct file-system indexing outside the container. Network filtering requires Apple `com.apple.developer.networking.networkextension` entitlement.
3. **Desktop (Windows/Linux/macOS)**: Running process termination and network socket binding inspection require elevated process privileges (e.g. Administrator or `sudo`/capabilities).
4. **Browser**: Extensions operate strictly within Manifest V3 bounds without unauthorized script injection or session hijacking.
