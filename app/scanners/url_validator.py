import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class URLValidationError(ValueError):
    pass


@dataclass
class ValidatedURL:
    url: str
    scheme: str
    hostname: str
    port: int | None
    resolved_ips: list[str]


UNSAFE_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}
METADATA_IPS = {ipaddress.ip_address("169.254.169.254")}


def validate_url(url, config):
    if not url or not str(url).strip():
        raise URLValidationError("The target URL is empty.")
    candidate = str(url).strip()
    if "\\" in candidate or candidate.startswith(("/", ".")):
        raise URLValidationError("Local file paths are not valid scan targets.")

    parsed = urlparse(candidate)
    if parsed.scheme.lower() in UNSAFE_SCHEMES:
        raise URLValidationError("Unsupported URL scheme. Use http:// or https:// only.")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise URLValidationError("Unsupported URL scheme. Use http:// or https:// only.")
    if parsed.username or parsed.password:
        raise URLValidationError("URLs containing embedded usernames or passwords are not allowed.")
    if not parsed.hostname:
        raise URLValidationError("The URL must include a valid hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The URL contains an invalid port number.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise URLValidationError("The URL contains an invalid port number.")

    hostname = parsed.hostname.lower().strip(".")
    _validate_domain_allowlist(hostname, config.get("ALLOWED_DOMAINS", []))
    resolved_ips = _resolve_host(hostname, port or (443 if parsed.scheme == "https" else 80))
    allow_local = bool(config.get("ALLOW_LOCAL_TARGETS", False))
    for ip_text in resolved_ips:
        _validate_ip_allowed(ipaddress.ip_address(ip_text), allow_local)
    return ValidatedURL(candidate, parsed.scheme.lower(), hostname, port, resolved_ips)


def _resolve_host(hostname, port):
    try:
        literal = ipaddress.ip_address(hostname.strip("[]"))
        return [str(literal)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise URLValidationError("DNS resolution failed for the supplied hostname.") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise URLValidationError("DNS resolution returned no usable addresses.")
    return ips


def _validate_ip_allowed(ip, allow_local):
    if allow_local:
        return
    if ip in METADATA_IPS:
        raise URLValidationError("Cloud metadata addresses are blocked.")
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise URLValidationError("Local, private, reserved, or non-public addresses are blocked.")


def _validate_domain_allowlist(hostname, allowlist):
    values = [item.lower().strip(".") for item in allowlist if item]
    if not values:
        return
    for allowed in values:
        if hostname == allowed or hostname.endswith(f".{allowed}"):
            return
    raise URLValidationError("This hostname is not permitted by the configured domain allowlist.")
