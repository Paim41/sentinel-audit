from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.forms import ScanForm
from app.models import Scan
from app.scans.services import compare_scans, run_scan, user_scan_limit_reached
from app.scanners.url_validator import URLValidationError


scans_bp = Blueprint("scans", __name__, url_prefix="/scans")


@scans_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    form = ScanForm()
    form.scan_profile.data = form.scan_profile.data or current_user.default_scan_profile or "standard"
    if form.validate_on_submit():
        if user_scan_limit_reached(current_user.id):
            flash("Scan rate limit reached. Please wait before starting another scan.", "warning")
            return redirect(url_for("scans.new"))
        try:
            scan = run_scan(
                current_user,
                form.target_url.data,
                form.scan_name.data.strip() if form.scan_name.data else None,
                form.scan_profile.data,
            )
        except URLValidationError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("scans.new"))
        if scan.status == "failed":
            flash(scan.error_message or "Scan failed safely.", "warning")
        else:
            flash("Scan completed.", "success")
        return redirect(url_for("scans.results", scan_id=scan.id))
    return render_template("scans/new.html", form=form, title="New Scan")


@scans_bp.route("/loading")
@login_required
def loading():
    return render_template("scans/loading.html", title="Scanning")


@scans_bp.route("/<int:scan_id>")
@login_required
def results(scan_id):
    scan = _owned_scan(scan_id)
    previous = (
        Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.target_host == scan.target_host,
            Scan.id != scan.id,
            Scan.completed_at < scan.completed_at,
        )
        .order_by(Scan.completed_at.desc())
        .first()
    )
    metrics = {metric.metric_name: metric.metric_value for metric in scan.metrics}
    return render_template("scans/results.html", scan=scan, previous=previous, metrics=metrics, title="Results")


@scans_bp.route("/history")
@login_required
def history():
    query = Scan.query.filter_by(user_id=current_user.id)
    search = request.args.get("q", "").strip()
    risk = request.args.get("risk", "").strip()
    profile = request.args.get("profile", "").strip()
    date_value = request.args.get("date", "").strip()
    score_min = request.args.get("score_min", type=int)
    score_max = request.args.get("score_max", type=int)
    if search:
        query = query.filter(Scan.target_url.contains(search))
    if risk:
        query = query.filter(Scan.risk_level == risk)
    if profile:
        query = query.filter(Scan.scan_profile == profile)
    if date_value:
        try:
            start = datetime.strptime(date_value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            query = query.filter(Scan.started_at >= start, Scan.started_at < start + timedelta(days=1))
        except ValueError:
            flash("Date filter ignored because it was not valid.", "warning")
    if score_min is not None:
        query = query.filter(Scan.security_score >= score_min)
    if score_max is not None:
        query = query.filter(Scan.security_score <= score_max)
    scans = query.order_by(Scan.started_at.desc()).all()
    return render_template("scans/history.html", scans=scans, title="Scan History")


@scans_bp.route("/<int:scan_id>/compare")
@login_required
def compare(scan_id):
    current = _owned_scan(scan_id)
    previous_id = request.args.get("previous_id", type=int)
    previous = _owned_scan(previous_id) if previous_id else (
        Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.target_host == current.target_host,
            Scan.id != current.id,
            Scan.completed_at < current.completed_at,
        )
        .order_by(Scan.completed_at.desc())
        .first()
    )
    if not previous:
        flash("No previous scan is available for this target.", "info")
        return redirect(url_for("scans.results", scan_id=current.id))
    comparison = compare_scans(previous, current)
    return render_template("scans/compare.html", comparison=comparison, title="Compare Scans")


@scans_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete(scan_id):
    scan = _owned_scan(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan deleted.", "info")
    return redirect(url_for("scans.history"))


def _owned_scan(scan_id):
    if not scan_id:
        abort(404)
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        abort(403)
    return scan
