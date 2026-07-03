from app.scanners.base import BaseScanner


TOKEN_NAMES = {
    "csrf",
    "csrf_token",
    "_csrf",
    "authenticity_token",
    "request_verification_token",
    "__requestverificationtoken",
    "token",
}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFScanner(BaseScanner):
    category = "CSRF Review"

    def scan(self):
        if not self.context.soup:
            return []
        findings = []
        for index, form in enumerate(self.context.soup.find_all("form"), start=1):
            method = (form.get("method") or "GET").upper()
            if method not in STATE_CHANGING_METHODS:
                continue
            names = {
                (field.get("name") or "").strip().lower()
                for field in form.find_all(["input", "textarea", "select"])
            }
            if names & TOKEN_NAMES:
                findings.append(self.finding(
                    "Token-like CSRF field detected",
                    "info",
                    "passed",
                    "A state-changing form includes a token-like field name.",
                    f"Form {index}: {', '.join(sorted(names & TOKEN_NAMES))}",
                    "Still verify server-side CSRF validation manually.",
                ))
            else:
                findings.append(self.finding(
                    "Possible missing CSRF protection",
                    "low",
                    "warning",
                    "A state-changing form did not expose a token-like field name. This is not a confirmed vulnerability.",
                    f"Form {index}: method={method}",
                    "Check whether framework-level CSRF, SameSite cookies, or custom headers protect this action.",
                ))
        return findings or [self.finding(
            "No state-changing HTML forms observed",
            "info",
            "info",
            "No POST, PUT, PATCH, or DELETE-like HTML forms were found on this page.",
            "No matching form methods detected.",
            "Review authenticated state-changing workflows separately.",
        )]
