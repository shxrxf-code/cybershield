/*
    CyberShield built-in YARA rules for document macros and archive abuse.

    Same caveat as cybershield_core.yar: these are pattern rules, not proof.
    Office documents legitimately contain macro projects and external links, so
    the rules here are written to require the *combination* of a macro project
    with a code-execution or persistence primitive rather than flagging either
    alone.
*/

import "pe"
import "math"

rule CyberShield_Document_Macro_Obfuscation
{
    meta:
        author = "CyberShield"
        description = "Macro project containing string-splitting/character-code obfuscation with execution"
        family = "malware"
        severity = "critical"
    strings:
        $has_vba = "vbaProject" nocase ascii wide
        $ob1 = "Chr(" nocase ascii wide
        $ob2 = "Mid(" nocase ascii wide
        $ob3 = "Asc(" nocase ascii wide
        $ob4 = "Environ(" nocase ascii wide
        $ex1 = "Application.Run" nocase ascii wide
        $ex2 = "Document_Open" nocase ascii wide
        $ex3 = "Workbook_Open" nocase ascii wide
        $ex4 = "AutoOpen" nocase ascii wide
        $sh1 = "WScript.Shell" nocase ascii wide
        $sh2 = "powershell" nocase ascii wide
        $sh3 = "Shell(" nocase ascii wide
    condition:
        $has_vba and (2 of ($ob*) or any of ($sh*)) and any of ($ex*)
}

rule CyberShell_Document_DDE_Fields
{
    meta:
        author = "CyberShield"
        description = "Word DDE field capable of launching a command without macro trust settings"
        family = "exploit"
        severity = "high"
    strings:
        $dde1 = "DDEAUTO" nocase ascii wide
        $dde2 = "DDE " nocase ascii wide
        $cmd1 = "\\system32\\cmd.exe" nocase ascii wide
        $cmd2 = "powershell" nocase ascii wide
        $cmd3 = "wscript" nocase ascii wide
        $cmd4 = "mshta" nocase ascii wide
    condition:
        any of ($dde*) and any of ($cmd*)
}

rule CyberShield_Document_External_Template_Injection
{
    meta:
        author = "CyberShield"
        description = "DDEAUTO external template reference, a no-macro code execution path in Word"
        family = "exploit"
        severity = "high"
    strings:
        $template = "TEMPLATE" nocase ascii wide
        $dde     = "DDEAUTO" nocase ascii wide
        $exec    = "cmd.exe" nocase ascii wide
        $ps      = "powershell" nocase ascii wide
    condition:
        $dde and $template and any of ($exec, $ps)
}

rule CyberShield_Archive_Executable_Disguise
{
    meta:
        author = "CyberShield"
        description = "A document-looking filename inside an archive carrying a real executable header"
        family = "malware"
        severity = "critical"
    strings:
        $mz   = { 4D 5A }
        $pdf  = "%PDF-" ascii
        $png  = { 89 50 4E 47 0D 0A 1A 0A }
        $jpg  = { FF D8 FF }
        $zip  = { 50 4B 03 04 }
    condition:
        // A real executable header at offset 0 alongside a document signature:
        // the file is two things at once, which no legitimate converter produces.
        $mz at 0 and 1 of ($pdf, $png, $jpg, $zip)
}

rule CyberShield_Archive_Polyglot_Lure
{
    meta:
        author = "CyberShield"
        description = "File with both a document signature and an executable signature"
        family = "malware"
        severity = "critical"
    strings:
        $pdf = "%PDF-" ascii
        $mz  = { 4D 5A }
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $rtf = "{\\rtf" ascii nocase
        $exeflag = "This program cannot be run in DOS mode" ascii nocase
    condition:
        $pdf and $mz
        or $rtf and $mz
        or $ole and $mz and $exeflag
}

rule CyberShield_Script_Obfuscation_PowerShell
{
    meta:
        author = "CyberShield"
        description = "PowerShell one-liner that assembles a command from character codes"
        family = "obfuscation"
        severity = "medium"
    strings:
        $join = "-join" nocase
        $chr  = "[char]" nocase
        $iex  = "IEX" nocase
        $dl   = "DownloadString" nocase
        $enc  = "-e " nocase
    condition:
        ($join and $chr and $iex) or ($chr and $iex and $dl) or ($chr and $iex and $enc)
}

rule CyberShield_Suspicious_Binary_Strings
{
    meta:
        author = "CyberShield"
        description = "Windows binary referencing process injection and anti-analysis together"
        family = "malware"
        severity = "high"
    strings:
        $inj1 = "VirtualAllocEx" ascii wide
        $inj2 = "WriteProcessMemory" ascii wide
        $inj3 = "CreateRemoteThread" ascii wide
        $inj4 = "NtMapViewOfSection" ascii wide
        $an1  = "IsDebuggerPresent" ascii wide
        $an2  = "CheckRemoteDebuggerPresent" ascii wide
        $an3  = "NtQueryInformationProcess" ascii wide
        $ev1  = "amsi.dll" ascii wide nocase
        $ev2  = "EtwEventWrite" ascii wide
    condition:
        2 of ($inj*) and (any of ($an*) or any of ($ev*))
}

rule CyberShield_Persistence_Run_Key_And_LOLBin
{
    meta:
        author = "CyberShield"
        description = "Persistence registry write combined with a living-off-the-land binary"
        family = "malware"
        severity = "high"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $l1 = "powershell.exe" ascii wide nocase
        $l2 = "mshta.exe" ascii wide nocase
        $l3 = "rundll32.exe" ascii wide nocase
        $l4 = "regsvr32.exe" ascii wide nocase
        $l5 = "wscript.exe" ascii wide nocase
    condition:
        any of ($r*) and 2 of ($l*)
}