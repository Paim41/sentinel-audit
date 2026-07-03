from urllib.parse import urlparse, urlunparse

from app.scanners.base import BaseScanner
from app.scanners.request_client import RequestClientError, SafeRequestClient


class HTTPSScanner(BaseScanner):
    category = "HTTPS"

    def scan(self):
        findings = []
        original = urlparse(self.context.original_url)
        final = urlparse(self.context.final_url or self.context.original_url)
        headers = self.context.response.headers if self.context.response is not None else {}

        if original.scheme == "https":
            findings.append(self.finding(
                "Original URL uses HTTPS",
                "info",
                "passed",
                "The submitted target uses HTTPS.",
                self.context.original_url,
                "Continue to serve sensitive pages through HTTPS only.",
            ))
        else:
            findings.append(self.finding(
                "Original URL uses HTTP",
                "medium",
                "warning",
                "The submitted URL starts with HTTP and relies on redirection or insecure transport.",
                self.context.original_url,
                "Prefer sharing and linking to the HTTPS version of the site.",
            ))
            findings.extend(self._check_http_to_https(original))

        if final.scheme == "https":
            findings.append(self.finding(
                "Final destination uses HTTPS",
                "info",
                "passed",
                "The final destination after redirects is protected by HTTPS.",
                self.context.final_url,
                "Keep redirects simple and consistently HTTPS.",
            ))
            hsts = headers.get("Strict-Transport-Security")
            if hsts:
                if "max-age=" in hsts.lower() and _hsts_max_age(hsts) >= 15552000:
                    status, severity, title = "passed", "info", "HSTS header is configured"
                else:
                    status, severity, title = "warning", "low", "HSTS max-age may be too short"
                findings.append(self.finding(
                    title,
                    severity,
                    status,
                    "HTTP Strict Transport Security helps browsers keep using HTTPS.",
                    f"Strict-Transport-Security: {hsts}",
                    "Use a meaningful max-age and review includeSubDomains/preload only after testing.",
                ))
            else:
                findings.append(self.finding(
                    "HSTS header is missing",
                    "low",
                    "warning",
                    "The HTTPS response did not include Strict-Transport-Security.",
                    "Header not found in the HTTP response.",
                    "Add HSTS after confirming all required subdomains support HTTPS.",
                ))
        else:
            findings.append(self.finding(
                "Website remains available through HTTP",
                "high",
                "failed",
                "The final destination is not HTTPS.",
                self.context.final_url or self.context.original_url,
                "Enable HTTPS and redirect HTTP requests to HTTPS.",
            ))
        if any(urlparse(item).scheme == "http" for item in self.context.redirect_chain):
            findings.append(self.finding(
                "Redirect chain includes HTTP destination",
                "medium",
                "warning",
                "At least one redirect destination used HTTP.",
                " -> ".join(self.context.redirect_chain),
                "Ensure every redirect step uses HTTPS where possible.",
            ))
        return findings

    def _check_http_to_https(self, parsed):
        client = SafeRequestClient(self.context.app_config)
        http_url = urlunparse(("http", parsed.netloc, parsed.path or "/", "", parsed.query, ""))
        try:
            result = client.request(http_url, method="GET", read_body=False)
        except RequestClientError as exc:
            return [self.finding(
                "HTTP redirect behaviour could not be verified",
                "info",
                "info",
                "The scanner could not safely verify whether HTTP redirects to HTTPS.",
                str(exc),
                "Manually confirm HTTP requests are redirected to HTTPS.",
            )]
        final = result.response.url
        if urlparse(final).scheme == "https" or any(urlparse(item).scheme == "https" for item in result.redirect_chain):
            return [self.finding(
                "HTTP redirects securely to HTTPS",
                "info",
                "passed",
                "The HTTP entry point redirects toward an HTTPS destination.",
                " -> ".join(result.redirect_chain or [final]),
                "Keep this redirect in place and avoid redirect chains returning to HTTP.",
            )]
        return [self.finding(
            "HTTP does not redirect to HTTPS",
            "medium",
            "warning",
            "The HTTP version did not appear to redirect to HTTPS.",
            final,
            "Configure a direct HTTP-to-HTTPS redirect.",
        )]


def _hsts_max_age(value):
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return 0
    return 0
