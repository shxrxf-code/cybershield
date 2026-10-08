/*
 * Document-delivery phishing rules.
 *
 * These cover the *delivery* side of phishing: lures embedded in documents and
 * rendered HTML, plus the office template-injection mechanism. Malware
 * behaviour, ransomware, coin-mining and financial-theft rules live in their own
 * files so that a rule file stays readable and reviewable.
 */

rule CyberShield_HTML_Invoice_Lure
{
    meta:
        description = "Document or HTML posing as an invoice or bill, with a call to action"
        author = "CyberShield"
        severity = "high"
        category = "phishing"
    strings:
        $doc_word = /(invoice|rechnung|facture|factuur|faktura|fattura|statement of account|remittance|payment advice|inv[- ]?no)/ nocase
        $urgency = /(overdue|past due|final notice|payment (is )?(required|pending|due)|amount due|act now|immediately|within 24 hours)/ nocase
        $cta = /(<a[^>]{0,200}href|to (view|download|settle|pay) (this|the) (invoice|document|statement|bill)|click (here|the link) to (view|download|settle)|follow the link below)/ nocase
        $remote = /(https?:\/\/[^\s"'<>]{10,})/ nocase
        $raw_ip = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $markup = /<\s*(html|body|table|div|p|span|a\s)/ nocase
    condition:
        $doc_word and $urgency and $cta and $markup and ($remote or $raw_ip)
}

rule CyberShield_Credential_Harvest_Page
{
    meta:
        description = "Rendered content that collects credentials from a look-alike or third-party login flow"
        author = "CyberShield"
        severity = "critical"
        category = "credential-theft"
        authoritative = "true"
    strings:
        $password_field = /<input[^>]{0,200}type\s*=\s*["']?password/ nocase
        $identity_field = /<input[^>]{0,200}(type\s*=\s*["']?email|name\s*=\s*["']?(user|login|username|email))[\s>]/ nocase
        $brand = /(paypal|microsoft|office 365|apple|icloud|google|netflix|amazon|facebook|instagram|whatsapp|linkedin|dropbox|chase|wells fargo|bank of america|barclays|lloyds|hsbc|santander|revolut|coinbase|metamask)/ nocase
        $impostor = /(sign in|log in|login|verify your (identity|account)|confirm your (identity|account)|secure(ly)? (sign in|log in)|session (has )?expired)/ nocase
        $auto_submit = /(document\.cookie|localStorage|XMLHttpRequest|sendBeacon|navigator\.sendBeacon|fetch\s*\(\s*["']https?:\/\/|\.submit\s*\(\s*\))/
        $cross_origin = /<form[^>]{0,300}action\s*=\s*["']https?:\/\// nocase
    condition:
        $password_field and $identity_field and $brand and $impostor
        and ($auto_submit or $cross_origin)
}

rule CyberShield_Link_Text_Mismatch_Invoice_Page
{
    meta:
        description = "Anchor text advertises a payment or document domain while href points elsewhere"
        author = "CyberShield"
        severity = "critical"
        category = "link-deception"
        authoritative = "true"
    strings:
        $anchor_text = /<a[^>]{0,200}>\s*(paypal|apple|microsoft|google|amazon|netflix|chase|wells fargo|bank|sign in|verify your account|secure (login|sign in|invoice|payment))[^<]{0,40}<\s*\/\s*a>/ nocase
        $href = /href\s*=\s*["'][^"']+["']/ nocase
        $payload_host = /(https?:\/\/[^"'\/]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|https?:\/\/[^"']*\.(tk|ml|ga|cf|gq|top|xyz|zip|mov|click|link|work|rest|cam|pw|club|buzz)([\/"'?\s]|$))/
        $data_uri = /href\s*=\s*["']\s*(javascript|data|vbscript):/ nocase
    condition:
        $anchor_text and $href and ($payload_host or $data_uri)
}

rule CyberShield_Obfuscated_JavaScript_Loader
{
    meta:
        description = "JavaScript that decodes a hidden payload before executing it"
        author = "CyberShield"
        severity = "high"
        category = "obfuscation"
    strings:
        $decode_exec = /(eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)|document\.write\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)|setTimeout\s*\(\s*atob|setInterval\s*\(\s*atob)/ nocase
        $hex_escape = /(\\x[0-9a-fA-F]{2}){12,}/ nocase
        $unicode_escape = /(\\u00[0-9a-fA-F]{2}){12,}/ nocase
        $charcode_series = /fromCharCode\s*\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}/ nocase
        $large_string = /["'][^"'\n]{200,}["']/ nocase
        $sink = /(document\.cookie|localStorage|eval\s*\(|new Function\s*\(|fetch\s*\(\s*["']https?:\/\/|XMLHttpRequest)/ nocase
    condition:
        $decode_exec and 1 of ($hex_escape, $unicode_escape, $charcode_series, $large_string) and $sink
}

rule CyberShield_Office_Template_Injection
{
    meta:
        description = "Office document using DDE, a remote template reference, or an OLE object that invokes a program"
        author = "CyberShield"
        severity = "high"
        category = "payload"
        authoritative = "true"
    strings:
        $dde = /(DDEAUTO|DDE |_HIDDEN|dde\.exe|Hidden\\)/ nocase
        $remote_template = /(file:\/\/\/[^"]+\.(dotm|dotx|docm|xlsm|pptm)|https?:\/\/[^"'\s]+\.(dotm|dotx|docm|xlsm|pptm))/
        $ole = /(oleObject|ProgID\s*=\s*"?\s*(Excel\.Sheet|Word\.Document|Package))/ nocase
        $program = /(cmd\s*\|\s*\/c|powershell(\.exe)?\s+-|MSEXCEL\.Application|Shell\.Application|winword\.exe|wscript\.exe|cscript\.exe|mshta\.exe)/ nocase
    condition:
        ($dde and $ole) or ($remote_template and $ole) or ($ole and $program)
}

rule CyberShield_Hidden_Attachment_Lure
{
    meta:
        description = "Message text that pressures the reader into opening or enabling a local file"
        author = "CyberShield"
        severity = "high"
        category = "phishing"
    strings:
        $enable = /(enable (macros|content|editing)|turn on macros|allow (macros|javascript)|allow this document|trusted documents|protected view)/ nocase
        $open_local = /(open the (attached )?(file|document|spreadsheet|worksheet)|double[- ]click (the|on) (file|attachment)|run the (attached )?(file|installer|setup)|attach(ment)? (is )?(included|enclosed) below)/ nocase
        $target = /(\.(exe|scr|bat|cmd|js|vbs|hta|jar|ps1|iso|img|lnk|apk|msi)\b|@echo|autorun)/ nocase
    condition:
        $target and $enable and $open_local
}

rule CyberShield_Document_Embedded_Executable_Signature
{
    meta:
        description = "A document carries an executable or archive signature, or an executable carries a document header"
        author = "CyberShield"
        severity = "critical"
        category = "polyglot"
        authoritative = "true"
    strings:
        $doc_magic = /(%PDF-[0-9]\.[0-9]|\{\\rtf1?|DOCTYPE html|<html[\s>]|Microsoft Word 2007\+|Rich Text Format)/ nocase
        $exe_magic = /(This program cannot be run in DOS mode|\x7fELF\x02\x01\x01|PK\x03\x04\x14\x00\x08\x00|#!\/bin\/(sh|ba)sh|\x1f\x8b\x08)/
        $cmd_exec = /(@echo\s+off[\s\S]{0,120}(powershell|cmd\s*\/c|wscript|mshta|certutil|bitsadmin|wget|curl)|cmd(\.exe)?\s*\/c\s*\/?c?\s*[^\r\n]{0,80}(certutil|bitsadmin|wget|curl|mshta))/
        $dos_stub_prefix = /^.{0,4}MZ.{20,400}(This program cannot be run in DOS mode)[\s\S]{0,400}(%PDF-|{\\rtf|<html)/ nocase
    condition:
        $cmd_exec or $dos_stub_prefix or ($doc_magic and $exe_magic)
}