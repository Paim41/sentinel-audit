from urllib.parse import urljoin, urlparse

from app.scanners.base import BaseScanner


SENSITIVE_TYPES = {"password", "email", "tel"}


class FormScanner(BaseScanner):
    category = "HTML Forms"

    def scan(self):
        if not self.context.soup:
            self.context.technical["form_count"] = "0"
            return [self.finding(
                "No HTML forms inspected",
                "info",
                "info",
                "No parseable HTML forms were found on the inspected page.",
                "No form elements detected.",
                "Inspect authenticated or JavaScript-rendered forms manually if applicable.",
            )]
        forms = self.context.soup.find_all("form")
        self.context.technical["form_count"] = str(len(forms))
        if not forms:
            return [self.finding(
                "No HTML forms detected",
                "info",
                "info",
                "The inspected page did not contain HTML form elements.",
                "0 forms found.",
                "No form-specific action is required for this page.",
            )]

        findings = []
        page_scheme = urlparse(self.context.final_url or self.context.original_url).scheme
        page_host = urlparse(self.context.final_url or self.context.original_url).hostname
        for index, form in enumerate(forms, start=1):
            method = (form.get("method") or "GET").upper()
            action = urljoin(self.context.final_url or self.context.original_url, form.get("action") or "")
            action_parsed = urlparse(action)
            inputs = form.find_all(["input", "select", "textarea"])
            input_types = [(field.get("type") or field.name).lower() for field in inputs]
            sensitive = sorted(set(item for item in input_types if item in SENSITIVE_TYPES))
            hidden_count = sum(1 for item in input_types if item == "hidden")
            summary = {
                "number": index,
                "method": method,
                "action": action,
                "fields": len(inputs),
                "sensitive": ", ".join(sensitive) or "none",
                "observations": [],
            }
            if action_parsed.scheme == "http":
                summary["observations"].append("Submits to HTTP")
                findings.append(self.finding(
                    "Form submits to HTTP",
                    "high",
                    "failed",
                    "A form action points to an insecure HTTP destination.",
                    f"Form {index}: {method} {action}",
                    "Submit forms only to HTTPS endpoints.",
                ))
            if method == "GET" and sensitive:
                summary["observations"].append("Sensitive fields use GET")
                findings.append(self.finding(
                    "Sensitive form fields use GET",
                    "medium",
                    "warning",
                    "Sensitive values submitted with GET can appear in URLs, browser history, and logs.",
                    f"Form {index}: sensitive fields {', '.join(sensitive)}",
                    "Use POST for forms that collect sensitive information.",
                ))
            if page_scheme != "https" and "password" in sensitive:
                summary["observations"].append("Password field on non-HTTPS page")
                findings.append(self.finding(
                    "Password field appears on non-HTTPS page",
                    "high",
                    "failed",
                    "A password field was detected while the page is not served over HTTPS.",
                    f"Form {index}: password input present.",
                    "Serve login and credential forms through HTTPS only.",
                ))
            if action_parsed.hostname and page_host and action_parsed.hostname != page_host:
                summary["observations"].append("Cross-domain action")
                findings.append(self.finding(
                    "Form posts to another domain",
                    "low",
                    "info",
                    "A form action points to a different hostname. This may be intentional.",
                    f"Form {index}: {action_parsed.hostname}",
                    "Manually verify the external form endpoint is trusted and expected.",
                ))
            if "password" in sensitive:
                password_fields = form.find_all("input", {"type": "password"})
                if any((field.get("autocomplete") or "").lower() not in {"current-password", "new-password"} for field in password_fields):
                    summary["observations"].append("Password autocomplete should be explicit")
                    findings.append(self.finding(
                        "Password autocomplete setting is not explicit",
                        "low",
                        "warning",
                        "Password managers work best when autocomplete hints are explicit.",
                        f"Form {index}: password autocomplete missing or uncommon.",
                        "Use autocomplete=current-password or new-password as appropriate.",
                    ))
            if not summary["observations"]:
                summary["observations"].append("No obvious form transport issue detected")
                findings.append(self.finding(
                    "Form transport checks passed",
                    "info",
                    "passed",
                    "The scanner did not observe obvious transport issues in this form.",
                    f"Form {index}: {method}, fields={len(inputs)}, hidden={hidden_count}",
                    "Continue manual review for business logic and server-side validation.",
                ))
            self.context.form_summaries.append(summary)
        return findings
