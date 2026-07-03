from app.scanners.score_calculator import calculate_score, risk_level_for_score


def test_risk_score_calculation_with_category_cap():
    findings = [
        {"category": "Headers", "severity": "high", "status": "warning"},
        {"category": "Headers", "severity": "high", "status": "failed"},
        {"category": "Headers", "severity": "high", "status": "failed"},
        {"category": "Cookies", "severity": "low", "status": "warning"},
        {"category": "TLS", "severity": "info", "status": "passed"},
    ]
    assert calculate_score(findings) == 67


def test_risk_level_boundaries():
    assert risk_level_for_score(95) == "Excellent"
    assert risk_level_for_score(82) == "Good"
    assert risk_level_for_score(60) == "Needs Improvement"
    assert risk_level_for_score(30) == "High Risk"
    assert risk_level_for_score(10) == "Critical Risk"
