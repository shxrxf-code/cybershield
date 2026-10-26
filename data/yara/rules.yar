/*
   CyberShield YARA Rule Set
   Covers standard test signatures, webshells, ransomware, credential dumpers, and obfuscation.
*/

rule EICAR_Test_File
{
    meta:
        description = "Standard Antivirus Test File"
        severity = "low"
        category = "test_file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Generic_PHP_Webshell
{
    meta:
        description = "Common PHP Web Shell Execution Patterns"
        severity = "high"
        category = "webshell"
    strings:
        $s1 = "eval(base64_decode(" nocase
        $s2 = "system($_GET[" nocase
        $s3 = "passthru($_POST[" nocase
        $s4 = "shell_exec($_REQUEST[" nocase
        $s5 = "assert($_POST[" nocase
        $s6 = "c99shell" nocase
        $s7 = "r57shell" nocase
    condition:
        any of ($s*)
}

rule Suspicious_PowerShell_DownloadCradle
{
    meta:
        description = "Obfuscated PowerShell Download & Execute Cradle"
        severity = "high"
        category = "dropper"
    strings:
        $p1 = "powershell -enc" nocase
        $p2 = "powershell.exe -w hidden -nop -ep bypass" nocase
        $p3 = "Net.WebClient).DownloadString(" nocase
        $p4 = "Invoke-Expression (New-Object" nocase
        $p5 = "IEX (New-Object" nocase
    condition:
        any of ($p*)
}

rule Ransomware_ShadowCopy_Tampering
{
    meta:
        description = "Ransomware Volume Shadow Copy Deletion Command"
        severity = "critical"
        category = "ransomware"
    strings:
        $r1 = "vssadmin delete shadows" nocase
        $r2 = "vssadmin.exe Delete Shadows /All /Quiet" nocase
        $r3 = "wmic shadowcopy delete" nocase
        $r4 = "bcdedit /set {default} recoveryenabled No" nocase
        $r5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $r6 = "wbadmin delete catalog -quiet" nocase
    condition:
        any of ($r*)
}

rule Mimikatz_LSASS_Dumper
{
    meta:
        description = "Mimikatz LSASS Memory and Credential Harvesting"
        severity = "critical"
        category = "credential_theft"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "privilege::debug" nocase
        $m4 = "kerberos::golden" nocase
        $m5 = "sekurlsa::minidump" nocase
    condition:
        2 of ($m*)
}

rule Reverse_Shell_Payload
{
    meta:
        description = "Common Reverse Shell Scripts"
        severity = "high"
        category = "backdoor"
    strings:
        $sh1 = "/bin/sh -i >& /dev/tcp/" nocase
        $sh2 = "/bin/bash -i >& /dev/tcp/" nocase
        $sh3 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" nocase
        $sh4 = "nc -e /bin/sh" nocase
        $sh5 = "nc -e /bin/bash" nocase
    condition:
        any of ($sh*)
}
