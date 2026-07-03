from http.cookies import SimpleCookie

from app.scanners.base import BaseScanner


class CookieScanner(BaseScanner):
    category = "Cookies"

    def scan(self):
        raw_headers = []
        try:
            raw_headers = self.context.response.raw.headers.get_all("Set-Cookie") or []
        except AttributeError:
            header = self.context.response.headers.get("Set-Cookie") if self.context.response else None
            if header:
                raw_headers = [header]
        if not raw_headers:
            self.context.technical["cookie_count"] = "0"
            return [self.finding(
                "No response cookies observed",
                "info",
                "info",
                "The target response did not set cookies on the inspected page.",
                "No Set-Cookie headers were present.",
                "Review authenticated and state-changing areas separately if they exist.",
            )]

        findings = []
        cookie_count = 0
        for header in raw_headers:
            cookie = SimpleCookie()
            try:
                cookie.load(header)
            except Exception:
                continue
            for name, morsel in cookie.items():
                cookie_count += 1
                summary = {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or "",
                    "path": morsel["path"] or "",
                    "domain": morsel["domain"] or "",
                    "expires": morsel["expires"] or "session",
                }
                self.context.cookie_summaries.append(summary)
                evidence = _mask_cookie(name, morsel)
                if not morsel["secure"]:
                    findings.append(self.finding(
                        "Secure attribute missing",
                        "medium",
                        "warning",
                        "A cookie was set without the Secure attribute.",
                        evidence,
                        "Set the Secure attribute for cookies that should only travel over HTTPS.",
                    ))
                if not morsel["httponly"]:
                    findings.append(self.finding(
                        "HttpOnly attribute missing",
                        "low",
                        "warning",
                        "A cookie was set without HttpOnly.",
                        evidence,
                        "Use HttpOnly for cookies that JavaScript does not need to read.",
                    ))
                if not morsel["samesite"]:
                    findings.append(self.finding(
                        "SameSite attribute missing",
                        "low",
                        "warning",
                        "A cookie did not declare SameSite behaviour.",
                        evidence,
                        "Set SameSite=Lax or SameSite=Strict where compatible.",
                    ))
                if morsel["secure"] and morsel["httponly"] and morsel["samesite"]:
                    findings.append(self.finding(
                        "Cookie configured with common security attributes",
                        "info",
                        "passed",
                        "A cookie includes Secure, HttpOnly, and SameSite attributes.",
                        evidence,
                        "Continue to avoid storing sensitive values directly in cookies.",
                    ))
        self.context.technical["cookie_count"] = str(cookie_count)
        return findings or [self.finding(
            "Cookie headers were present but could not be parsed",
            "info",
            "info",
            "Set-Cookie headers existed but did not parse cleanly.",
            "Cookie values were not displayed.",
            "Manually review cookie attributes in a browser or proxy.",
        )]


def _mask_cookie(name, morsel):
    attrs = []
    for attr in ("secure", "httponly", "samesite", "path", "domain", "expires"):
        if morsel[attr]:
            attrs.append(f"{attr}={morsel[attr] if attr not in {'secure', 'httponly'} else 'true'}")
    return f"{name}=[redacted]; " + "; ".join(attrs)
