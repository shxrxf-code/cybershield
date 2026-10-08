"""Tunable constants and knowledge bases used by the analysis engines.

Everything here is data, not logic, so it can be reviewed, extended and unit
tested independently of the code that consumes it.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------- #
# Phishing / social-engineering lexicons
# --------------------------------------------------------------------------- #

#: Tokens that commonly appear in credential-harvesting and urgency language.
#: Presence of any single token is *never* sufficient for a malicious verdict.
PHISHING_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "login", "log-in", "signin", "sign-in", "verify", "verification", "validate",
        "account", "secure", "security", "update", "password", "passwd", "wallet",
        "payment", "bank", "banking", "urgent", "immediately", "confirm",
        "confirmation", "suspended", "suspend", "locked", "unlock", "recover",
        "recovery", "reset", "credential", "credentials", "authenticate",
        "authorization", "unusual", "expire", "expiring", "limited", "alert",
        "warning", "invoice", "billing", "refund", "verify your identity",
        "ssn", "social-security", "seed-phrase", "recovery-phrase", "2fa",
        "otp", "one-time", "webscr", "webscrd",
    }
)

#: Brand names commonly impersonated in phishing.  Used for similarity checks
#: against the URL host, never as a standalone verdict.
IMPERSONATED_BRANDS: Final[dict[str, tuple[str, ...]]] = {
    "apple": ("apple.com", "icloud.com", "appleid.apple.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"),
    "google": ("google.com", "gmail.com", "googleusercontent.com", "goo.gl"),
    "amazon": ("amazon.com", "amazon.co.uk", "aws.amazon.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "linkedin": ("linkedin.com",),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "telegram": ("telegram.org", "t.me"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "blockchain": ("blockchain.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "irs": ("irs.gov"),
    "hmrc": ("hmrc.gov.uk", "gov.uk"),
    "netflix-billing": ("netflix.com",),
    "steam": ("steampowered.com",),
    "roblox": ("roblox.com"),
    "discord": ("discord.com", "discord.gg"),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "office365": ("office.com", "microsoft.com"),
    "okta": ("okta.com"),
    "docusign-support": ("docusign.com",),
    "wetransfer": ("wetransfer.com"),
    "adobe": ("adobe.com",),
    "dji": ("dji.com"),
}

#: URL shorteners.  A shortener is not malicious but hides the real destination, so
#: it triggers a "destination hidden" observation and forces redirect analysis.
URL_SHORTENERS: Final[frozenset[str]] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly",
        "tiny.cc", "shorte.st", "t.ly", "lnkd.in", "db.tt", "qr.ae", "v.gd",
        "s.id", "soo.gd", "clck.ru", "u.to", "x.co", "short.io", "hyperurl.co",
        "bl.ink", "mcaf.ee", "j.gs", "1url.com", "yourls.org", "linktr.ee",
        "urlz.fr", "shrtco.de", "gg.gg", "trib.al", "po.st",
    }
)

#: TLDs with a persistently high share of abuse/abuse reports.  Used as a weak,
#: low-weight signal only.
SUSPICIOUS_TLDS: Final[frozenset[str]] = frozenset(
    {
        "zip", "mov", "review", "country", "kim", "cricket", "science", "work",
        "party", "gq", "tk", "ml", "cf", "ga", "top", "buzz", "click", "link",
        "loan", "download", "racing", "win", "bid", "stream", "date", "faith",
        "accountant", "men", "trade", "cam", "surf", "quest", "cyou", "sbs",
        "icu", "monster", "lol", "autos", "bar", "best",
    }
)

#: Top-level domains whose registrars/policies correlate with phishing campaigns.
#: These are frequently abused by legitimate brand phishing, so a hit is a
#: meaningful (but not conclusive) signal.
PHISHING_PRONE_TLDS: Final[frozenset[str]] = frozenset(
    {"zip", "mov", "review", "kim", "cricket", "country", "work", "party", "top", "click"}
)

#: Non-standard ports historically associated with C2 panels, credential stuffing
#: or drive-by-download infrastructure.
SUSPICIOUS_PORTS: Final[frozenset[int]] = frozenset(
    {21, 22, 23, 25, 69, 80, 445, 465, 587, 808, 1080, 1234, 2222, 3128, 3306,
     3389, 4444, 4445, 5555, 5900, 6666, 6667, 8000, 8008, 8081, 8443, 8888,
     9001, 9090, 9200, 9443, 10000, 11371, 31337, 50050}
)

#: Ports considered "expected" for their scheme; used to flag protocol confusion.
WELL_KNOWN_PORTS: Final[frozenset[int]] = frozenset({80, 443, 8080, 8443})

# --------------------------------------------------------------------------- #
# General security lexicon
# --------------------------------------------------------------------------- #

#: Windows executable / script extensions worth flagging inside documents and
#: archives (delivery vectors for endpoint compromise).
EXECUTABLE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".hta",
        ".jar", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1",
        ".bat", ".cmd", ".sh", ".py", ".pyc", ".pl", ".rb", ".apk", ".lnk",
        ".reg", ".chm", ".gadget", ".msc", ".inf", ".cab", ".iso", ".img",
    }
)

#: Extensions that are frequently used to disguise executables.
DOUBLE_EXTENSION_HINTS: Final[tuple[str, ...]] = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".gif", ".zip", ".csv", ".rtf",
)

#: HTML/script fragments that indicate an embedded (not merely linked) payload.
SUSPICIOUS_EMBED_TOKENS: Final[tuple[str, ...]] = (
    "<script", "javascript:", "vbscript:", "<iframe", "<object", "<embed",
    "<applet", "eval(", "unescape(", "fromcharcode(", "powershell",
    "cmd.exe", "wscript.shell", "activexobject", "msxml2.xmlhttp",
    "adodb.stream", "shell(", "exec(", "system(", "popen(", "base64_decode",
    "document.write", "createElement('script'",
)

#: Office/OpenXML relationship targets that lead to remote templates or macros.
SUSPICIOUS_OFFICE_RELATIONSHIPS: Final[frozenset[str]] = frozenset(
    {
        "externalLink", "oleObject", "package", "attachedTemplate",
        "vbaProject", "frame", "hyperlink", "externalReference", "customXml",
    }
)

#: APK permissions grouped by abuse potential.  A permission is a *risk
#: contributor*, never an automatic malicious verdict.
RISKY_PERMISSIONS: Final[dict[str, str]] = {
    "android.permission.SEND_SMS": "SMS: can send premium-rate or phishing messages",
    "android.permission.RECEIVE_SMS": "SMS: can silently intercept 2FA codes",
    "android.permission.READ_SMS": "SMS: can read one-time passcodes",
    "android.permission.READ_CONTACTS": "Contacts: enables targeted social engineering",
    "android.permission.WRITE_CONTACTS": "Contacts: can modify or exfiltrate address books",
    "android.permission.RECORD_AUDIO": "Microphone: covert audio capture risk",
    "android.permission.CAMERA": "Camera: covert photo/video capture risk",
    "android.permission.ACCESS_FINE_LOCATION": "Location: precise tracking capability",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Location: covert background tracking",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility: can read all on-screen content and simulate taps",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay: enables tapjacking over other apps",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Installer: can silently sideload more apps",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Storage: unrestricted filesystem access",
    "android.permission.READ_EXTERNAL_STORAGE": "Storage: reads user media/documents",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Storage: writes to shared storage",
    "android.permission.REQUEST_DELETE_PACKAGES": "Installer: can remove other apps",
    "android.permission.DEVICE_ADMIN": "Device admin: hard to uninstall, resists removal",
    "android.permission.KILL_BACKGROUND_PROCESSES": "Process: can terminate security apps",
    "android.permission.FOREGROUND_SERVICE": "Service: allows persistent background execution",
    "android.permission.INTERNET": "Network: outbound communication",
    "android.permission.READ_PHONE_STATE": "Device info: device/SIM fingerprinting",
    "android.permission.READ_PHONE_NUMBERS": "Device info: reads phone number",
    "android.permission.USE_SIP": "Telephony: can place SIP calls",
    "android.permission.PROCESS_OUTGOING_CALLS": "Telephony: can intercept outgoing calls",
    "android.permission.BLUETOOTH": "Bluetooth: proximity-based data access",
    "android.permission.BODY_SENSORS": "Sensors: biometric/health data access",
    "android.permission.QUERY_ALL_PACKAGES": "App inventory: reconnaissance of installed apps",
    "android.permission.PACKAGE_USAGE_STATS": "App usage: user behaviour profiling",
    "android.permission.SYSTEM_ALERT": "System: legacy overlay capability",
}

#: Permissions that are effectively harmless / expected for most apps; requesting
#: them should not influence the score at all.
BENIGN_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.ACCESS_COARSE_LOCATION",
    }
)

#: Android API-level transitions worth surfacing in reports.
API_VERSION_NAMES: Final[dict[int, str]] = {
    21: "Android 5.0",
    22: "Android 5.1",
    23: "Android 6.0",
    24: "Android 7.0",
    25: "Android 7.1",
    26: "Android 8.0",
    27: "Android 8.1",
    28: "Android 9.0",
    29: "Android 10",
    30: "Android 11",
    31: "Android 12",
    32: "Android 12L",
    33: "Android 13",
    34: "Android 14",
    35: "Android 15",
    36: "Android 16",
}

# --------------------------------------------------------------------------- #
# File type detection
# --------------------------------------------------------------------------- #

#: Magic-byte signatures used when ``libmagic`` is unavailable.  Kept in sync
#: with the container so that MIME detection never depends solely on extension.
MAGIC_SIGNATURES: Final[tuple[tuple[bytes, str, str], ...]] = (
    (b"%PDF-", "application/pdf", "pdf"),
    (b"PK\x03\x04", "application/zip", "zip"),
    (b"PK\x05\x06", "application/zip", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "ole"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"\xff\xd8\xff", "image/jpeg", "jpeg"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
    (b"II*\x00", "image/tiff", "tiff"),
    (b"MM\x00*", "image/tiff", "tiff"),
    (b"RIFF", "image/webp", "webp"),
    (b"\x7fELF", "application/x-elf", "elf"),
    (b"MZ", "application/x-msdownload", "pe"),
    (b"\xca\xfe\xba\xbe", "application/java-vm", "mach-o-fat"),
    (b"dex\n", "application/x-dex", "dex"),
    (b"\x50\x4b\x03\x04", "application/zip", "zip"),
    (b"{\\rtf", "application/rtf", "rtf"),
    (b"\x1f\x8b", "application/gzip", "gzip"),
    (b"BZh", "application/x-bzip2", "bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7z"),
    (b"\x04\x22\x4d\x18", "application/x-lz4", "lz4"),
    (b"\x28\xb5\x2f\xfd", "application/zstd", "zstd"),
    (b"msg822", "application/vnd.ms-outlook", "msg"),
    (b"\x78\x01", "application/zlib", "zlib"),
    (b"\x78\x9c", "application/zlib", "zlib"),
)

#: Map of extension -> (canonical MIME, object type).
EXTENSION_MAP: Final[dict[str, tuple[str, str]]] = {
    ".pdf": ("application/pdf", "document"),
    ".doc": ("application/msword", "document"),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document"),
    ".xls": ("application/vnd.ms-excel", "document"),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document"),
    ".ppt": ("application/vnd.ms-powerpoint", "document"),
    ".pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "document"),
    ".rtf": ("application/rtf", "document"),
    ".txt": ("text/plain", "text"),
    ".csv": ("text/csv", "text"),
    ".md": ("text/markdown", "text"),
    ".log": ("text/plain", "text"),
    ".eml": ("message/rfc822", "email"),
    ".msg": ("application/vnd.ms-outlook", "email"),
    ".png": ("image/png", "image"),
    ".jpg": ("image/jpeg", "image"),
    ".jpeg": ("image/jpeg", "image"),
    ".gif": ("image/gif", "image"),
    ".webp": ("image/webp", "image"),
    ".tif": ("image/tiff", "image"),
    ".tiff": ("image/tiff", "image"),
    ".bmp": ("image/bmp", "image"),
    ".zip": ("application/zip", "archive"),
    ".gz": ("application/gzip", "archive"),
    ".tar": ("application/x-tar", "archive"),
    ".7z": ("application/x-7z-compressed", "archive"),
    ".rar": ("application/vnd.rar", "archive"),
    ".apk": ("application/vnd.android.package-archive", "apk"),
    ".exe": ("application/x-msdownload", "binary"),
    ".dll": ("application/x-msdownload", "binary"),
    ".elf": ("application/x-elf", "binary"),
    ".dex": ("application/x-dex", "binary"),
    ".jar": ("application/java-archive", "binary"),
    ".html": ("text/html", "text"),
    ".htm": ("text/html", "text"),
}

#: True when the detected MIME belongs to a family that normally does *not*
#: execute anything, i.e. a macro-free document surface.
INERT_MIME_TYPES: Final[frozenset[str]] = frozenset(
    {
        "image/png", "image/jpeg", "image/gif", "image/webp", "image/tiff",
        "image/bmp", "text/plain", "text/csv", "text/markdown",
    }
)

#: Shannon-entropy thresholds (bits per byte) for "is this packed/encrypted?".
ENTROPY_PACKED = 7.5
ENTROPY_HIGH = 7.0
ENTROPY_NORMAL = 6.0

#: Maximum sizes enforced by the analyzers themselves (defence in depth; the API
#: layer also enforces limits).
MAX_ANALYSIS_SIZE = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRY_SIZE = 50 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ANALYSIS_DEPTH = 3

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

DISCLAIMER: Final[str] = (
    "CyberShield performs automated static analysis. No automated scanner can "
    "guarantee a verdict: false positives (safe content flagged) and false "
    "negatives (harmful content missed) are possible. Treat the verdict as "
    "decision support and confirm with your own judgement before acting."
)

UNKNOWN_DISCLAIMER: Final[str] = (
    "CyberShield could not gather enough evidence to classify this object. "
    "This does NOT mean it is safe. Scan again later, scan with additional "
    "engines enabled, or investigate manually."
)

VERDICT_ACTIONS: Final[dict[str, str]] = {
    "SAFE": "No action required. Keep normal security hygiene.",
    "LOW RISK": "No immediate action. Note the observations if the source is unexpected.",
    "SUSPICIOUS": "Do not interact with this object until you have reviewed the report.",
    "HIGH RISK": "Avoid this object. Verify the sender or source through a known-good channel.",
    "MALICIOUS": "Do not open, run or install. Quarantine or delete the object.",
    "UNKNOWN": "Insufficient evidence. Re-scan or escalate for manual analysis.",
}

VERDICT_COLORS: Final[dict[str, str]] = {
    "SAFE": "#16A34A",
    "LOW RISK": "#65A30D",
    "SUSPICIOUS": "#D97706",
    "HIGH RISK": "#EA580C",
    "MALICIOUS": "#DC2626",
    "UNKNOWN": "#64748B",
}