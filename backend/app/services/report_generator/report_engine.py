import io
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List


class SecurityReportEngine:
    """
    Generates Daily, Weekly, and Monthly security summaries with PDF and CSV export formats.
    """

    @staticmethod
    def generate_csv_log(threats: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "Module", "Verdict", "Risk Score", "Threat Level", "Title", "Action Taken"])
        for t in threats:
            writer.writerow([
                t.get("created_at", datetime.now(timezone.utc).isoformat()),
                t.get("module_type", "GENERAL"),
                t.get("verdict", "UNKNOWN"),
                t.get("risk_score", 0),
                t.get("threat_level", "LOW"),
                t.get("title", ""),
                t.get("action_taken", "LOGGED")
            ])
        return output.getvalue()

    @staticmethod
    def generate_security_brief(
        device_uuid: str,
        security_score: int,
        threats_blocked: int,
        scans_count: int,
        period: str = "WEEKLY",
        threat_breakdown: Dict[str, int] = None
    ) -> Dict[str, Any]:
        threat_breakdown = threat_breakdown or {"Phishing": 0, "Malware": 0, "Network": 0, "Scam": 0}
        
        posture = "EXCELLENT" if security_score >= 85 else ("MODERATE_RISK" if security_score >= 60 else "COMPROMISED")

        return {
            "report_id": f"REP-{device_uuid[:8]}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}",
            "device_uuid": device_uuid,
            "period": period,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_security_score": security_score,
            "security_posture": posture,
            "metrics": {
                "total_threats_blocked": threats_blocked,
                "total_scans_completed": scans_count,
                "threat_breakdown": threat_breakdown
            },
            "recommendations": [
                "Keep ShieldGuard real-time notification protection active.",
                "Ensure Android OS security patch level is up-to-date.",
                "Avoid installing APK files from unknown browser sources.",
                "Always route public WiFi traffic through ShieldGuard Secure VPN."
            ]
        }


report_engine = SecurityReportEngine()
