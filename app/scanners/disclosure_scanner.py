import re

from app.scanners.base import BaseScanner


DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
]


class DisclosureScanner(BaseScanner):
    category = "Information Disclosure"

    def scan(self):
        headers = self.context.response.headers if self.context.response is not None else {}
        findings = []
        for header in DISCLOSURE_HEADERS:
            value = headers.get(header)
            if not value:
                continue
            severity = "low" if _contains_version(value) else "info"
            findings.append(self.finding(
                f"{header} header exposes implementation details",
                severity,
                "info" if severity == "info" else "warning",
                "The response includes software or infrastructure information. This does not automatically mean the software is vulnerable.",
                f"{header}: {value}",
                "Suppress unnecessary version or platform details where operationally appropriate.",
            ))
        return findings or [self.finding(
            "No common software disclosure headers observed",
            "info",
            "passed",
            "The inspected response did not include the common disclosure headers checked by Sentinel Audit.",
            "Checked Server, X-Powered-By, ASP.NET, generator, and proxy headers.",
            "Continue to avoid exposing unnecessary implementation details.",
        )]


def _contains_version(value):
    return bool(re.search(r"\d+\.\d+", value or ""))
