/*
    CyberShield built-in YARA rules.

    Scope and honest limits
    -----------------------
    These rules are original, derived from publicly documented malware
    behaviour and the structure of common file formats. They are NOT extracted
    from any vendor signature set, and they are not a replacement for a
    commercial or ClamAV signature database. A YARA rule is a *pattern match*,
    not proof: packed or freshly built malware routinely defeats patterns like
    these, and legitimate software occasionally contains the same byte sequences.
    That is why the risk engine treats a rule match as strong evidence rather
    than a certainty, and why a report states confidence and reasons rather than
    asserting safety.

    Rules here describe:
      * loader/dropper templates that fetch and execute a second stage
      * credential-stealing and keylogging primitives referenced by name
      * known C2 configuration structures and beacon markers
      * packer/crypter entry stubs, which are suspicious but not conclusive

    Do not add rules that are only "suspicious strings" - they will generate
    false positives on real software. Prefer structural patterns.
*/

import "pe"
import "math"

rule CyberShield_Dropper_PowerShell_Encoded
{
    meta:
        author = "CyberShield"
        description = "PowerShell invoked with an encoded command and download/execute"
        family = "generic_dropper"
        severity = "high"
        reference = "Detects the pattern of a launcher that decodes and runs a hidden payload"
    strings:
        $enc1 = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "FromBase64String" nocase
        $exe1 = "IEX(" nocase
        $exe2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Net.WebClient" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $wmi = "Win32_Process" nocase
    condition:
        (any of ($enc*) and any of ($exe*)) and
        (any of ($dl*) or $hidden or $bypass or $wmi)
}

rule CyberShield_Dropper_Certutil_Urlcache
{
    meta:
        author = "CyberShield"
        description = "certutil used to fetch a remote file into the URL cache then run it"
        family = "generic_dropper"
        severity = "high"
    strings:
        $c1 = "certutil" nocase
        $c2 = "-urlcache" nocase
        $c3 = "-split" nocase
        $c4 = "-decode" nocase
        $r1 = "IEX(" nocase
        $r2 = "Start-Process" nocase
    condition:
        $c1 and $c2 and (any of ($r*) or $c3 or $c4)
}

rule CyberShield_Loader_MSHTML_Execution
{
    meta:
        author = "CyberShield"
        description = "mshta/MSHTML execution switch, used to run script without a normal host process"
        family = "generic_loader"
        severity = "high"
    strings:
        $a = "mshta.exe" nocase
        $b = "MSHTML:" nocase
        $c = "-mht" nocase
        $d = "rundll32.exe" nocase
        $e = "javascript:" nocase
    condition:
        ($a and any of ($b, $c)) or ($d and any of ($b, $e))
}

rule CyberShield_Credential_Theft_References
{
    meta:
        author = "CyberShield"
        description = "Programmatic references to browser credential stores and crypto wallets"
        family = "credential_stealer"
        severity = "critical"
        rationale = "No legitimate business application enumerates all of these at once"
    strings:
        $chrome  = "Login Data" nocase
        $cookies = "Cookies" nocase
        $logins  = "logins.json" nocase
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "electrum" nocase
        $wallet3 = "exodus" nocase
        $ssh     = "\\.ssh\\id_rsa" nocase wide
        $keylog  = "GetAsyncKeyState" nocase
        $keylog2 = "SetWindowsHookEx" nocase
    condition:
        (2 of ($chrome, $cookies, $logins) or any of ($wallet*) or $ssh)
        and any of ($keylog, $keylog2)
}

rule CyberShield_Ransomware_Shadow_Deletion
{
    meta:
        author = "CyberShield"
        description = "Volume shadow copy deletion and ransom note behaviour"
        family = "ransomware"
        severity = "critical"
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "wmic shadowcopy delete" nocase
        $vss3 = "bcdedit /set {default}" nocase
        $note1 = "your files have been encrypted" nocase
        $note2 = "to decrypt your files" nocase
        $note3 = "send bitcoin to" nocase
        $note4 = "decryption key" nocase
        $proc = "taskkill /f /im" nocase
    condition:
        any of ($vss*) and (any of ($note*) or $proc)
}

rule CyberShield_Packed_High_Entropy_Section
{
    meta:
        author = "CyberShield"
        description = "PE with a high-entropy section, a common packer indicator"
        family = "packer"
        severity = "medium"
        caveat = "Legitimate software is also packed; treat as a prompt to look closer"
    condition:
        pe.is_pe and pe.number_of_sections > 1 and
        for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 1024 and
            math.entropy(pe.sections[i].raw_data_offset,
                         math.min(pe.sections[i].raw_data_size, 65535)) > 7.4
        )
}

rule CyberShield_C2_Beacon_Config
{
    meta:
        author = "CyberShield"
        description = "C2 configuration structure: URL plus port plus interval keys near a host string"
        family = "c2"
        severity = "critical"
    strings:
        $k1 = "beacon_interval" nocase
        $k2 = "sleep_time" nocase
        $k3 = "poll_interval" nocase
        $k4 = "c2_server" nocase
        $k5 = "callback_url" nocase
        // \x2f is "/" and \x5c is "\". YARA regex literals are delimited by "/", so
// those two characters are written as escapes rather than literally.
$u1 = /https?(:|\x2f\x2f)[a-z0-9\-\.]{4,60}\x2f[a-z0-9_\-]{2,40}\x2e(php|jsp|aspx|cgi)/ nocase
    condition:
        any of ($k*) and $u1
}

rule CyberShield_Office_Macro_Autoexec
{
    meta:
        author = "CyberShield"
        description = "Office macro that auto-executes and reaches a script or shell"
        family = "dropper"
        severity = "critical"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Open" nocase
        $sh1 = "Shell" nocase
        $sh2 = "WScript.Shell" nocase
        $sh3 = "powershell" nocase
        $sh4 = "CreateObject" nocase
    condition:
        any of ($auto*) and any of ($sh*)
}

rule CyberShield_PDF_Embedded_Launcher
{
    meta:
        author = "CyberShield"
        description = "PDF carrying both an embedded launch action and a script/URI action"
        family = "exploit"
        severity = "high"
    strings:
        $open = "/OpenAction" nocase
        $js  = "/JavaScript" nocase
        $uri = "/URI" nocase
        $launch = "/Launch" nocase
        $aa = "/AA" nocase
    condition:
        $open and (2 of ($js, $uri, $launch, $aa))
}

rule CyberShield_Android_Overlay_Abuse
{
    meta:
        author = "CyberShield"
        description = "Dex string evidence of overlay-based credential capture"
        family = "android_malware"
        severity = "critical"
    strings:
        $s1 = "SYSTEM_ALERT_WINDOW" nocase
        $s2 = "TYPE_APPLICATION_OVERLAY" nocase
        $s3 = "AccessibilityService" nocase
        $s4 = "android/accessibilityservice" nocase
        $s5 = "BIND_ACCESSIBILITY_SERVICE" nocase
    condition:
        ($s1 and $s2) or (2 of ($s3, $s4, $s5))
}

rule CyberShield_Android_SMS_Interception
{
    meta:
        author = "CyberShield"
        description = "Dex evidence of SMS interception, a banking-trojan primitive"
        family = "android_banking_trojan"
        severity = "critical"
    strings:
        $s1 = "android.provider.Telephony.SMS_RECEIVED" nocase
        $s2 = "pdus" nocase
        $s3 = "getSubscriberId" nocase
        $s4 = "getDeviceId" nocase
        $s5 = "android.intent.action.BOOT_COMPLETED" nocase
        $s6 = "RECEIVE_SMS" nocase
    condition:
        ($s1 and $s2) or ($s6 and any of ($s3, $s4, $s5))
}

rule CyberShield_Suspicious_Script_Wrapper
{
    meta:
        author = "CyberShield"
        description = "Script that decodes an obfuscated payload at runtime"
        family = "obfuscation"
        severity = "medium"
    strings:
        $a1 = "eval(atob(" nocase
        $a2 = "eval(unbase64(" nocase
        $a3 = "exec(base64_decode(" nocase
        $a4 = "Invoke-Expression ([System.Text.Encoding]::UTF8.GetString(" nocase
        $a5 = "\\x65\\x76\\x61\\x6c\\x28" nocase
        $a6 = "String.fromCharCode(" nocase
    condition:
        any of them
}