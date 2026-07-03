from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, render_template, send_file, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Scan
from app.reports.pdf_generator import generate_scan_pdf


reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).all()
    return render_template("reports/index.html", scans=scans, title="Reports")


@reports_bp.route("/<int:scan_id>/print")
@login_required
def printable(scan_id):
    scan = _owned_scan(scan_id)
    metrics = {metric.metric_name: metric.metric_value for metric in scan.metrics}
    return render_template("reports/printable.html", scan=scan, metrics=metrics, title="Printable Report")


@reports_bp.route("/<int:scan_id>/download")
@login_required
def download(scan_id):
    scan = _owned_scan(scan_id)
    metrics = {metric.metric_name: metric.metric_value for metric in scan.metrics}
    filename = f"sentinel-audit-scan-{scan.id}.pdf"
    path = Path(current_app.config["REPORTS_DIR"]) / filename
    try:
        generate_scan_pdf(scan, metrics, path)
    except Exception:
        current_app.logger.exception("PDF generation failed")
        flash("PDF generation failed. Please try again.", "danger")
        return redirect(url_for("scans.results", scan_id=scan.id))
    return send_file(path, as_attachment=True, download_name=filename, mimetype="application/pdf")


def _owned_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        from flask import abort
        abort(404)
    return scan
