import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ON_VERCEL = bool(os.environ.get("VERCEL"))


def _bool_env(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:////tmp/sentinel_audit.db"
        if ON_VERCEL
        else f"sqlite:///{BASE_DIR / 'instance' / 'sentinel_audit.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    ALLOW_LOCAL_TARGETS = _bool_env("ALLOW_LOCAL_TARGETS", False if ON_VERCEL else True)
    ALLOWED_DOMAINS = [
        item.strip().lower()
        for item in os.environ.get("ALLOWED_DOMAINS", "").split(",")
        if item.strip()
    ]
    REQUEST_CONNECT_TIMEOUT = _int_env("REQUEST_CONNECT_TIMEOUT", 5)
    REQUEST_READ_TIMEOUT = _int_env("REQUEST_READ_TIMEOUT", 10)
    MAX_REDIRECTS = _int_env("MAX_REDIRECTS", 3)
    MAX_RESPONSE_BYTES = _int_env("MAX_RESPONSE_BYTES", 2 * 1024 * 1024)
    SCAN_RATE_LIMIT = _int_env("SCAN_RATE_LIMIT", 5)
    SCAN_RATE_WINDOW_MINUTES = _int_env("SCAN_RATE_WINDOW_MINUTES", 10)
    REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/tmp/sentinel-audit-reports" if ON_VERCEL else BASE_DIR / "reports"))


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    ALLOW_LOCAL_TARGETS = False
    SERVER_NAME = "localhost.localdomain"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
