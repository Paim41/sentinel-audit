from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from flask import current_app

from app.extensions import db
from app.models import Finding, Scan, ScanMetric, utc_now
from app.scanners.base import ScanContext, make_finding
from app.scanners.cookie_scanner import CookieScanner
from app.scanners.csrf_scanner import CSRFScanner
from app.scanners.disclosure_scanner import DisclosureScanner
from app.scanners.exposure_scanner import ExposureScanner
from app.scanners.form_scanner import FormScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.https_scanner import HTTPSScanner
from app.scanners.mixed_content_scanner import MixedContentScanner
from app.scanners.request_client import RequestClientError, SafeRequestClient
from app.scanners.score_calculator import calculate_score, risk_level_for_score
from app.scanners.tls_scanner import TLSScanner
from app.scanners.url_validator import URLValidationError, validate_url


QUICK_SCANNERS = [
    HTTPSScanner,
    HeaderScanner,
    CookieScanner,
    FormScanner,
    CSRFScanner,
    DisclosureScanner,
]
STANDARD_EXTRA_SCANNERS = [TLSScanner, MixedContentScanner, ExposureScanner]


def user_scan_limit_reached(user_id):
    limit = int(current_app.config.get("SCAN_RATE_LIMIT", 5))
    window = int(current_app.config.get("SCAN_RATE_WINDOW_MINUTES", 10))
    since = utc_now() - timedelta(minutes=window)
    recent_count = Scan.query.filter(
        Scan.user_id == user_id,
        Scan.started_at >= since,
        Scan.status.in_(["completed", "failed", "running"]),
    ).count()
    return recent_count >= limit


def run_scan(user, target_url, scan_name, profile):
    validated = validate_url(target_url, current_app.config)
    scan = Scan(
        user_id=user.id,
        scan_name=scan_name,
        target_url=validated.url,
        target_host=validated.hostname,
        scan_profile=profile,
        status="running",
        started_at=utc_now(),
    )
    db.session.add(scan)
    db.session.commit()

    try:
        context, findings = _perform_scan(validated.url, profile)
        score = calculate_score(findings)
        scan.final_url = context.final_url
        scan.target_host = context.target_host or validated.hostname
        scan.status = "completed"
        scan.security_score = score
        scan.risk_level = risk_level_for_score(score)
        scan.http_status = context.technical.get("http_status")
        scan.response_time = context.technical.get("response_time")
        scan.redirect_count = len(context.redirect_chain)
        scan.completed_at = utc_now()
        scan.duration_seconds = _duration_seconds(scan.started_at, scan.completed_at)
        _persist_findings(scan, findings)
        _persist_metrics(scan, context)
    except (URLValidationError, RequestClientError) as exc:
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = utc_now()
        scan.duration_seconds = _duration_seconds(scan.started_at, scan.completed_at)
        _persist_findings(scan, [_error_finding(str(exc))])
    except Exception as exc:
        current_app.logger.exception("Scan failed unexpectedly")
        scan.status = "failed"
        scan.error_message = "The scan could not be completed safely."
        scan.completed_at = utc_now()
        scan.duration_seconds = _duration_seconds(scan.started_at, scan.completed_at)
        _persist_findings(scan, [_error_finding(str(exc))])
    db.session.commit()
    return scan


def _perform_scan(target_url, profile):
    client = SafeRequestClient(current_app.config)
    result = client.request(target_url, method="GET", read_body=True)
    response = result.response
    final_url = response.url
    parsed = urlparse(final_url)
    content_type = response.headers.get("Content-Type", "")
    html = ""
    soup = None
    findings = []
    if "html" in content_type.lower() or not content_type:
        html = result.body.decode(response.encoding or "utf-8", errors="replace")
        soup = BeautifulSoup(html, "html.parser")
    else:
        findings.append(make_finding(
            "Content",
            "Unsupported content type for HTML analysis",
            "low",
            "info",
            "The target did not return an HTML page, so HTML-specific checks were limited.",
            f"Content-Type: {content_type}",
            "Run Sentinel Audit against an HTML page for form, CSRF, and mixed-content checks.",
        ))
    context = ScanContext(
        original_url=target_url,
        profile=profile,
        app_config=current_app.config,
        final_url=final_url,
        target_host=parsed.hostname,
        response=response,
        html=html,
        soup=soup,
        redirect_chain=result.redirect_chain,
        technical={
            "http_status": response.status_code,
            "response_time": round(result.elapsed_seconds, 3),
            "content_type": content_type or "unknown",
            "final_url": final_url,
            "redirect_count": len(result.redirect_chain),
        },
    )
    scanners = list(QUICK_SCANNERS)
    if profile == "standard":
        scanners.extend(STANDARD_EXTRA_SCANNERS)
    for scanner_class in scanners:
        try:
            findings.extend(scanner_class(context).scan())
        except Exception as exc:
            current_app.logger.warning("%s failed: %s", scanner_class.__name__, exc)
            findings.append(make_finding(
                scanner_class.category,
                f"{scanner_class.category} check could not be completed",
                "info",
                "info",
                "This scanner encountered a safe handling error and did not complete.",
                str(exc),
                "Retry the scan or review this area manually.",
            ))
    return context, findings


def _duration_seconds(started_at, completed_at):
    started = _as_utc(started_at)
    completed = _as_utc(completed_at)
    return max(0.0, (completed - started).total_seconds())


def _as_utc(value):
    if value is None:
        return utc_now()
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _persist_findings(scan, findings):
    for item in findings:
        fingerprint = Finding.make_fingerprint(item["category"], item["title"], item["severity"])
        db.session.add(Finding(scan=scan, fingerprint=fingerprint, **item))


def _persist_metrics(scan, context):
    metrics = {
        "headers_checked": context.technical.get("headers_checked", "0"),
        "form_count": context.technical.get("form_count", "0"),
        "cookie_count": context.technical.get("cookie_count", "0"),
        "content_type": context.technical.get("content_type", "unknown"),
        "tls_issuer": context.tls_summary.get("issuer", ""),
        "tls_expiry": context.tls_summary.get("not_after", ""),
        "tls_days_remaining": str(context.tls_summary.get("days_remaining", "")),
    }
    for key, value in metrics.items():
        db.session.add(ScanMetric(scan=scan, metric_name=key, metric_value=str(value)))


def _error_finding(message):
    return make_finding(
        "Scan Error",
        "Scan could not be completed",
        "info",
        "info",
        "The scanner stopped before completing all checks.",
        message,
        "Review the URL, connectivity, local laboratory settings, and allowlist configuration.",
    )


def compare_scans(previous, current):
    previous_map = {finding.fingerprint: finding for finding in previous.findings}
    current_map = {finding.fingerprint: finding for finding in current.findings}
    previous_keys = set(previous_map)
    current_keys = set(current_map)
    new_findings = [current_map[key] for key in sorted(current_keys - previous_keys)]
    resolved_findings = [previous_map[key] for key in sorted(previous_keys - current_keys)]
    unchanged = [current_map[key] for key in sorted(current_keys & previous_keys)]
    return {
        "previous": previous,
        "current": current,
        "score_difference": (current.security_score or 0) - (previous.security_score or 0),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged,
        "improved_categories": _category_delta(previous, current, improved=True),
        "regressed_categories": _category_delta(previous, current, improved=False),
    }


def _category_delta(previous, current, improved):
    def failed_by_category(scan):
        counts = {}
        for finding in scan.findings:
            if finding.status in {"failed", "warning"}:
                counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts
    prev = failed_by_category(previous)
    curr = failed_by_category(current)
    categories = sorted(set(prev) | set(curr))
    result = []
    for category in categories:
        delta = curr.get(category, 0) - prev.get(category, 0)
        if improved and delta < 0:
            result.append((category, abs(delta)))
        if not improved and delta > 0:
            result.append((category, delta))
    return result
