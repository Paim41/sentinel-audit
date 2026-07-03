from dataclasses import dataclass, field
from typing import Any


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_STATUSES = {"passed", "failed", "warning", "info"}


def make_finding(category, title, severity, status, description, evidence, recommendation):
    severity = severity.lower()
    status = status.lower()
    if severity not in ALLOWED_SEVERITIES:
        severity = "info"
    if status not in ALLOWED_STATUSES:
        status = "info"
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "status": status,
        "description": description,
        "evidence": str(evidence or "No evidence recorded."),
        "recommendation": recommendation,
    }


@dataclass
class ScanContext:
    original_url: str
    profile: str
    app_config: dict
    final_url: str | None = None
    target_host: str | None = None
    response: Any | None = None
    html: str = ""
    soup: Any | None = None
    redirect_chain: list[str] = field(default_factory=list)
    tls_summary: dict[str, Any] = field(default_factory=dict)
    form_summaries: list[dict[str, Any]] = field(default_factory=list)
    cookie_summaries: list[dict[str, Any]] = field(default_factory=list)
    technical: dict[str, Any] = field(default_factory=dict)


class BaseScanner:
    category = "General"

    def __init__(self, context: ScanContext):
        self.context = context

    def finding(self, title, severity, status, description, evidence, recommendation):
        return make_finding(
            self.category, title, severity, status, description, evidence, recommendation
        )

    def scan(self):
        return []
