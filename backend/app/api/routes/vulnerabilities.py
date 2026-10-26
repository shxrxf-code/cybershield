from fastapi import APIRouter
from core.engine.detectors.vulnerability import perform_vulnerability_scan, scan_listening_ports, audit_system_configurations

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Scanner"])

@router.get("/")
def get_vulnerabilities():
    return perform_vulnerability_scan()

@router.post("/scan")
def trigger_vulnerability_scan():
    return perform_vulnerability_scan()

@router.get("/ports")
def get_open_ports():
    ports = scan_listening_ports()
    return {"ports": ports, "count": len(ports)}

@router.get("/configurations")
def get_configuration_findings():
    findings = audit_system_configurations()
    return {"findings": findings, "count": len(findings)}

@router.get("/status")
def status():
    return {"module": "vulnerability_scanner", "enabled": True, "engine": "CyberShield-VulnEngine-1.0", "status": "operational"}
