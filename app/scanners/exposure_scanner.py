from urllib.parse import urljoin, urlparse, urlunparse

from app.scanners.base import BaseScanner
from app.scanners.request_client import RequestClientError, SafeRequestClient


SAFE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/debug",
    "/test",
    "/backup.zip",
    "/config.old",
    "/.env",
]
SENSITIVE_PATHS = {"/debug", "/test", "/backup.zip", "/config.old", "/.env"}


class ExposureScanner(BaseScanner):
    category = "Public File Exposure"

    def scan(self):
        base = self._base_url()
        client = SafeRequestClient(self.context.app_config)
        findings = []
        for path in SAFE_PATHS:
            url = urljoin(base, path)
            try:
                result = client.head_or_small_get(url)
            except RequestClientError as exc:
                findings.append(self.finding(
                    f"{path} could not be checked safely",
                    "info",
                    "info",
                    "The scanner skipped this public-path check after a safe request error.",
                    str(exc),
                    "Review manually only if this path matters to your application.",
                ))
                continue
            response = result.response
            status = response.status_code
            content_type = response.headers.get("Content-Type", "unknown")
            content_length = response.headers.get("Content-Length", str(len(result.body)))
            evidence = f"HTTP {status}; Content-Type: {content_type}; Content-Length: {content_length}"
            if status in {200, 204, 206, 301, 302, 307, 308} and path in SENSITIVE_PATHS:
                findings.append(self.finding(
                    f"{path} appears publicly accessible",
                    "high" if path in {"/.env", "/backup.zip", "/config.old"} else "medium",
                    "failed",
                    "A sensitive-looking fixed path responded as publicly accessible. Contents were not displayed or stored.",
                    evidence,
                    "Restrict this path, remove the file, or return a non-public response.",
                ))
            elif status in {200, 204, 206}:
                findings.append(self.finding(
                    f"{path} is publicly available",
                    "info",
                    "info",
                    "This known public path is accessible. That may be expected.",
                    evidence,
                    "Confirm the content is intended for public access and does not expose secrets.",
                ))
            else:
                findings.append(self.finding(
                    f"{path} is not publicly accessible",
                    "info",
                    "passed",
                    "The path did not return an accessible success response.",
                    evidence,
                    "No action is required unless this file should be public.",
                ))
        return findings

    def _base_url(self):
        parsed = urlparse(self.context.final_url or self.context.original_url)
        return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
