import hashlib
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    default_scan_profile = db.Column(db.String(20), default="standard")
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    scans = db.relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    scan_name = db.Column(db.String(160), nullable=True)
    target_url = db.Column(db.Text, nullable=False)
    target_host = db.Column(db.String(255), nullable=False, index=True)
    final_url = db.Column(db.Text)
    scan_profile = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(30), default="pending", nullable=False)
    security_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(40), default="Unknown")
    http_status = db.Column(db.Integer)
    response_time = db.Column(db.Float)
    redirect_count = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True))
    duration_seconds = db.Column(db.Float, default=0)
    error_message = db.Column(db.Text)

    user = db.relationship("User", back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    metrics = db.relationship("ScanMetric", back_populates="scan", cascade="all, delete-orphan")

    @property
    def display_name(self):
        return self.scan_name or self.target_host

    def count_status(self, status):
        return sum(1 for finding in self.findings if finding.status == status)

    def count_severity(self, severity):
        return sum(1 for finding in self.findings if finding.severity == severity)


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    category = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    scan = db.relationship("Scan", back_populates="findings")

    @staticmethod
    def make_fingerprint(category, title, severity):
        raw = f"{category}|{title}|{severity}".lower().encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class ScanMetric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    metric_name = db.Column(db.String(120), nullable=False)
    metric_value = db.Column(db.Text, nullable=False)

    scan = db.relationship("Scan", back_populates="metrics")
