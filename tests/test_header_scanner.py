from app.scanners.base import ScanContext
from app.scanners.header_scanner import HeaderScanner


class DummyResponse:
    def __init__(self, headers):
        self.headers = headers


def test_header_scanner_reports_missing_headers():
    context = ScanContext(
        original_url="https://example.com",
        profile="quick",
        app_config={},
        response=DummyResponse({}),
    )
    findings = HeaderScanner(context).scan()
    titles = {finding["title"] for finding in findings}
    assert "Content-Security-Policy header is missing" in titles
    assert context.technical["headers_checked"] == "9"


def test_header_scanner_accepts_nosniff():
    context = ScanContext(
        original_url="https://example.com",
        profile="quick",
        app_config={},
        response=DummyResponse({"X-Content-Type-Options": "nosniff"}),
    )
    findings = HeaderScanner(context).scan()
    assert any(finding["title"] == "X-Content-Type-Options header is present" for finding in findings)
