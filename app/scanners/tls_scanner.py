import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.scanners.base import BaseScanner


class TLSScanner(BaseScanner):
    category = "TLS Certificate"

    def scan(self):
        parsed = urlparse(self.context.final_url or self.context.original_url)
        if parsed.scheme != "https":
            return [self.finding(
                "TLS certificate not inspected",
                "info",
                "info",
                "TLS certificate checks apply only to HTTPS targets.",
                "Final URL is not HTTPS.",
                "Enable HTTPS to make certificate validation possible.",
            )]
        host = parsed.hostname
        port = parsed.port or 443
        timeout = int(self.context.app_config.get("REQUEST_CONNECT_TIMEOUT", 5))
        try:
            cert = _fetch_certificate(host, port, timeout)
        except (ssl.SSLError, OSError) as exc:
            return [self.finding(
                "Certificate could not be verified",
                "high",
                "failed",
                "The scanner could not complete a verified TLS handshake.",
                str(exc),
                "Check the certificate chain, hostname, and TLS configuration.",
            )]

        not_before = _parse_cert_time(cert.get("notBefore"))
        not_after = _parse_cert_time(cert.get("notAfter"))
        days_remaining = (not_after - datetime.now(timezone.utc)).days if not_after else None
        subject = _flatten_name(cert.get("subject", []))
        issuer = _flatten_name(cert.get("issuer", []))
        sans = [item[1] for item in cert.get("subjectAltName", []) if item[0].lower() == "dns"]
        self.context.tls_summary = {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat() if not_before else "",
            "not_after": not_after.isoformat() if not_after else "",
            "days_remaining": days_remaining,
            "sans": ", ".join(sans[:8]),
        }

        findings = [self.finding(
            "Certificate is valid for the hostname",
            "info",
            "passed",
            "A verified TLS connection was established for the target hostname.",
            f"Issuer: {issuer}; expires: {not_after.date() if not_after else 'unknown'}",
            "Monitor certificate expiry and renew before service impact.",
        )]
        if days_remaining is not None:
            if days_remaining < 0:
                findings.append(self.finding(
                    "Certificate is expired",
                    "high",
                    "failed",
                    "The TLS certificate expiry date is in the past.",
                    f"Expired {-days_remaining} days ago.",
                    "Renew and deploy a valid certificate immediately.",
                ))
            elif days_remaining <= 7:
                findings.append(self.finding(
                    "Certificate expires within 7 days",
                    "high",
                    "warning",
                    "The TLS certificate is close to expiry.",
                    f"{days_remaining} days remaining.",
                    "Renew the certificate as soon as possible.",
                ))
            elif days_remaining <= 30:
                findings.append(self.finding(
                    "Certificate expires within 30 days",
                    "medium",
                    "warning",
                    "The TLS certificate should be renewed soon.",
                    f"{days_remaining} days remaining.",
                    "Schedule renewal and confirm automation is working.",
                ))
            else:
                findings.append(self.finding(
                    "Certificate expiry window is healthy",
                    "info",
                    "passed",
                    "The certificate is not close to expiry.",
                    f"{days_remaining} days remaining.",
                    "Keep renewal monitoring active.",
                ))
        return findings


def _fetch_certificate(host, port, timeout):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert()


def _parse_cert_time(value):
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _flatten_name(name):
    parts = []
    for group in name:
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
