import re
from typing import Dict, Any, List

SUSPICIOUS_MACRO_CALLS = [
    "wscript.shell", "powershell", "cmd.exe", "urldownloadtofile",
    "shellexecute", "autoopen", "document_open", "workbook_open",
    "createthread", "virtualalloc", "rundll32"
]

SUSPICIOUS_PDF_OBJECTS = [
    "/javascript", "/js", "/launch", "/embeddedfiles", "/openaction",
    "/aa", "/richmedia", "/xfa"
]


class DocumentSecurityEngine:
    def __init__(self):
        pass

    def analyze_document_metadata(
        self,
        file_name: str,
        file_extension: str,
        file_size_bytes: int,
        has_macros: bool,
        embedded_scripts: List[str] = None,
        embedded_urls: List[str] = None,
        suspicious_tags: List[str] = None
    ) -> Dict[str, Any]:
        embedded_scripts = embedded_scripts or []
        embedded_urls = embedded_urls or []
        suspicious_tags = [t.lower() for t in (suspicious_tags or [])]
        ext = file_extension.lower().strip(".")

        risk_score = 0
        exploit_indicators = []
        quarantine = False

        # 1. Office Documents Macro & OLE Analysis
        if ext in ["doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm"]:
            if has_macros or ext in ["docm", "xlsm", "pptm"]:
                risk_score += 35
                exploit_indicators.append("Document contains active VBA Macros / Executable Code")

                # Check script contents for weaponization
                script_body = " ".join(embedded_scripts).lower()
                for call in SUSPICIOUS_MACRO_CALLS:
                    if call in script_body:
                        risk_score += 25
                        exploit_indicators.append(f"Weaponized macro payload indicator detected: '{call}'")
                        quarantine = True

            # External template injection (Follina / CVE-2022-30190)
            for url in embedded_urls:
                if any(x in url.lower() for x in [".dotm", ".docm", "ms-msdt:", "payload"]):
                    risk_score += 40
                    exploit_indicators.append(f"Remote template injection exploit signature found: {url}")
                    quarantine = True

        # 2. PDF Exploits & Malicious Streams
        elif ext == "pdf":
            for tag in SUSPICIOUS_PDF_OBJECTS:
                if tag in suspicious_tags:
                    if tag in ["/javascript", "/js"]:
                        risk_score += 30
                        exploit_indicators.append("PDF contains embedded interactive JavaScript engine")
                    elif tag == "/launch":
                        risk_score += 45
                        exploit_indicators.append("Critical PDF Exploit: Uses /Launch action to execute OS commands")
                        quarantine = True
                    elif tag == "/openaction":
                        risk_score += 15
                        exploit_indicators.append("Automatic trigger on open (/OpenAction tag)")
                    elif tag == "/embeddedfiles":
                        risk_score += 20
                        exploit_indicators.append("PDF embeds hidden secondary files/payloads")

        # Clamp score
        risk_score = min(max(risk_score, 0), 100)

        if risk_score >= 70 or quarantine:
            verdict = "MALICIOUS"
            threat_level = "CRITICAL" if quarantine else "HIGH"
            safe_to_open = False
            quarantine = True
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
            safe_to_open = False
        else:
            verdict = "SAFE"
            threat_level = "LOW"
            safe_to_open = True

        return {
            "file_name": file_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "exploit_indicators": exploit_indicators,
            "macro_risk": has_macros or (ext in ["docm", "xlsm"]),
            "safe_to_open": safe_to_open,
            "quarantine_recommended": quarantine
        }


document_engine = DocumentSecurityEngine()
