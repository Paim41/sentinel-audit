from collections import defaultdict


SEVERITY_DEDUCTIONS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}
CATEGORY_LIMIT = 30


def calculate_score(findings):
    deductions_by_category = defaultdict(int)
    for finding in findings:
        if finding.get("status") not in {"failed", "warning"}:
            continue
        severity = finding.get("severity", "info")
        deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        category = finding.get("category", "General")
        deductions_by_category[category] = min(CATEGORY_LIMIT, deductions_by_category[category] + deduction)
    total = sum(deductions_by_category.values())
    return max(0, 100 - total)


def risk_level_for_score(score):
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Needs Improvement"
    if score >= 25:
        return "High Risk"
    return "Critical Risk"
