from app.scanners.base import BaseScanner


class HeaderScanner(BaseScanner):
    category = "Security Headers"

    EXPECTED = {
        "Content-Security-Policy": "A CSP can reduce the impact of cross-site scripting and content injection.",
        "Strict-Transport-Security": "HSTS helps browsers keep using HTTPS after the first secure visit.",
        "X-Content-Type-Options": "nosniff prevents some MIME type confusion issues.",
        "X-Frame-Options": "Frame controls reduce clickjacking exposure for older browsers.",
        "Referrer-Policy": "A referrer policy limits sensitive URL leakage to other sites.",
        "Permissions-Policy": "Permissions Policy limits access to browser features.",
        "Cross-Origin-Opener-Policy": "COOP helps isolate browsing contexts.",
        "Cross-Origin-Resource-Policy": "CORP helps control which origins may load resources.",
        "Cross-Origin-Embedder-Policy": "COEP supports stronger cross-origin isolation when needed.",
    }

    def scan(self):
        headers = self.context.response.headers if self.context.response is not None else {}
        findings = []
        for header, description in self.EXPECTED.items():
            value = headers.get(header)
            if not value:
                severity = "medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "low"
                findings.append(self.finding(
                    f"{header} header is missing",
                    severity,
                    "warning",
                    f"Missing defensive header. {description}",
                    "Header not found in the HTTP response.",
                    f"Review whether {header} is appropriate for this application and configure it carefully.",
                ))
                continue
            findings.append(self._evaluate_header(header, value, description))
        self.context.technical["headers_checked"] = str(len(self.EXPECTED))
        return findings

    def _evaluate_header(self, header, value, description):
        lower = value.lower()
        if header == "X-Content-Type-Options" and lower.strip() != "nosniff":
            return self.finding(
                "X-Content-Type-Options value should normally be nosniff",
                "low",
                "warning",
                description,
                f"{header}: {value}",
                "Set X-Content-Type-Options to nosniff unless there is a documented exception.",
            )
        if header == "X-Frame-Options" and lower.strip() not in {"deny", "sameorigin"}:
            return self.finding(
                "X-Frame-Options value may be weak",
                "low",
                "warning",
                description,
                f"{header}: {value}",
                "Use DENY or SAMEORIGIN, or use frame-ancestors in CSP for modern control.",
            )
        if header == "Referrer-Policy" and lower.strip() in {"unsafe-url", "origin-when-cross-origin"}:
            return self.finding(
                "Referrer-Policy may disclose more information than necessary",
                "low",
                "warning",
                description,
                f"{header}: {value}",
                "Prefer strict-origin-when-cross-origin or a stricter policy after testing.",
            )
        if header == "Strict-Transport-Security" and "max-age=" not in lower:
            return self.finding(
                "HSTS header is missing max-age",
                "low",
                "warning",
                description,
                f"{header}: {value}",
                "Include a tested max-age directive in the HSTS header.",
            )
        if header == "Content-Security-Policy" and ("unsafe-inline" in lower or "*" in lower):
            return self.finding(
                "Content-Security-Policy should be manually reviewed",
                "low",
                "warning",
                "A CSP exists, but broad sources or unsafe directives may reduce its value.",
                f"{header}: {value}",
                "Tighten the policy gradually and test in report-only mode before enforcement.",
            )
        return self.finding(
            f"{header} header is present",
            "info",
            "passed",
            description,
            f"{header}: {value}",
            "Continue reviewing this header as the application changes.",
        )
