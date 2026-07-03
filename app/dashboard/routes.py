from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from app.extensions import db
from app.forms import SettingsForm
from app.models import Finding, Scan


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.started_at.desc())
        .limit(8)
        .all()
    )
    all_scans = Scan.query.filter_by(user_id=current_user.id, status="completed").all()
    total_scans = len(all_scans)
    average_score = round(sum(scan.security_score or 0 for scan in all_scans) / total_scans) if total_scans else 0
    high_risk_findings = (
        Finding.query.join(Scan)
        .filter(Scan.user_id == current_user.id, Finding.severity.in_(["critical", "high"]))
        .count()
    )
    passed = warning = failed = info = 0
    for scan in all_scans:
        passed += scan.count_status("passed")
        warning += scan.count_status("warning")
        failed += scan.count_status("failed")
        info += scan.count_status("info")
    recent_for_chart = list(reversed(all_scans[-10:]))
    risk_counts = {
        "Critical": sum(scan.count_severity("critical") for scan in all_scans),
        "High": sum(scan.count_severity("high") for scan in all_scans),
        "Medium": sum(scan.count_severity("medium") for scan in all_scans),
        "Low": sum(scan.count_severity("low") for scan in all_scans),
        "Informational": sum(scan.count_severity("info") for scan in all_scans),
    }
    return render_template(
        "dashboard/index.html",
        title="Dashboard",
        scans=scans,
        total_scans=total_scans,
        average_score=average_score,
        high_risk_findings=high_risk_findings,
        resolved_findings=passed,
        overview={"passed": passed, "warning": warning, "failed": failed, "info": info},
        score_labels=[scan.started_at.strftime("%b %d") for scan in recent_for_chart],
        score_values=[scan.security_score for scan in recent_for_chart],
        risk_counts=risk_counts,
    )


@dashboard_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm(obj=current_user)
    if form.validate_on_submit():
        current_user.default_scan_profile = form.default_scan_profile.data
        db.session.commit()
        flash("Preferences saved.", "success")
        return redirect(url_for("dashboard.settings"))
    form.default_scan_profile.data = current_user.default_scan_profile or "standard"
    form.request_timeout.data = current_app.config.get("REQUEST_READ_TIMEOUT")
    form.maximum_redirects.data = current_app.config.get("MAX_REDIRECTS")
    form.pdf_preference.data = "detailed"
    return render_template(
        "settings.html",
        title="Settings",
        form=form,
        allow_local_targets=current_app.config.get("ALLOW_LOCAL_TARGETS"),
        allowed_domains=current_app.config.get("ALLOWED_DOMAINS") or [],
    )
