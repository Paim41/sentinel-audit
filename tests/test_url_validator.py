import socket

import pytest

from app.scanners.url_validator import URLValidationError, validate_url


def config(allow_local=False, allowlist=None):
    return {"ALLOW_LOCAL_TARGETS": allow_local, "ALLOWED_DOMAINS": allowlist or []}


def test_blocks_localhost_when_local_mode_disabled():
    with pytest.raises(URLValidationError):
        validate_url("http://localhost:5000", config(False))


def test_allows_localhost_when_local_mode_enabled():
    result = validate_url("http://localhost:5000", config(True))
    assert result.hostname == "localhost"


def test_blocks_private_ip_addresses():
    with pytest.raises(URLValidationError):
        validate_url("http://192.168.1.10", config(False))


def test_rejects_unsafe_schemes():
    with pytest.raises(URLValidationError):
        validate_url("file:///etc/passwd", config(True))


def test_blocks_disallowed_domain(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(URLValidationError):
        validate_url("https://example.org", config(False, ["example.com"]))
