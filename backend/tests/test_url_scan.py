import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.engine.detectors.url import analyze_url
from core.engine.scoring import compute_risk_score

def test_malicious_url_detection():
    url = "http://login-secure-update.evil.top/verify?redirect=http://bad.com"
    det = analyze_url(url)
    assert det['suspicious'] is True
    risk = compute_risk_score(det['features'])
    assert risk['score'] >= 40
    assert risk['level'] in ['high', 'critical', 'severe']

def test_benign_url():
    url = "https://www.google.com/"
    det = analyze_url(url)
    risk = compute_risk_score(det['features'])
    assert risk['score'] < 40
