import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.engine.detectors.apps import analyze_running_processes
from core.engine.detectors.browser import analyze_browser_url, analyze_download_safety, analyze_extension_permissions
from core.engine.detectors.ransomware import calculate_shannon_entropy, deploy_canaries, verify_canaries
from core.engine.detectors.vulnerability import perform_vulnerability_scan, scan_listening_ports
from core.engine.scoring import compute_risk_score

def test_apps_process_analysis():
    procs = analyze_running_processes(limit=10)
    assert isinstance(procs, list)
    assert len(procs) > 0
    first = procs[0]
    assert "pid" in first
    assert "name" in first
    assert "risk_score" in first

def test_browser_phishing_detection():
    # Test brand impersonation phishing URL
    res = analyze_browser_url("http://paypal-security-update.fake-portal.com/login", has_password_field=True, is_https=False)
    assert res["is_phishing"] is True
    assert res["risk_score"] >= 70
    assert res["action"] == "block"

def test_browser_download_safety():
    # Test double extension executable
    res = analyze_download_safety("financial_report.pdf.exe", "http://192.168.1.100/drop")
    assert res["is_dangerous"] is True
    assert res["risk_score"] >= 60

def test_browser_extension_permissions():
    manifest = {
        "name": "SuperAdblock",
        "version": "1.0",
        "permissions": ["<all_urls>", "webRequestBlocking", "cookies"]
    }
    res = analyze_extension_permissions(manifest)
    assert res["risk_score"] >= 60
    assert "webRequestBlocking" in res["excessive_permissions"]

def test_ransomware_entropy_calculation():
    # Plain text should have moderate entropy (~3-4)
    plain = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFF" * 10
    entropy_plain = calculate_shannon_entropy(plain)
    assert entropy_plain < 5.0

    # Random / pseudo-encrypted bytes should have high entropy (~7-8)
    import os
    random_bytes = os.urandom(512)
    entropy_rand = calculate_shannon_entropy(random_bytes)
    assert entropy_rand > 7.0

def test_ransomware_canary_tripwires():
    deploy_res = deploy_canaries()
    assert deploy_res["deployed_count"] > 0
    verify_res = verify_canaries()
    assert verify_res["status"] == "secure"
    assert verify_res["intact_canaries"] > 0

def test_vulnerability_scan():
    vuln_res = perform_vulnerability_scan()
    assert "security_score" in vuln_res
    assert 0 <= vuln_res["security_score"] <= 100
    assert isinstance(vuln_res["open_ports"], list)
    assert isinstance(vuln_res["remediations"], list)
