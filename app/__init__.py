import logging
from pathlib import Path

from flask import Flask, render_template

from app.extensions import csrf, db, login_manager
from app.models import User
from config import config_by_name


def create_app(config_name="development"):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.INFO)
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.scans.routes import scans_bp
    from app.reports.routes import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)

    register_security_headers(app)
    register_error_handlers(app)
    register_commands(app)

    with app.app_context():
        db.create_all()

    return app


def register_security_headers(app):
    @app.after_request
    def set_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'",
        )
        return response


def register_error_handlers(app):
    for code in (400, 403, 404, 429, 500):
        app.register_error_handler(
            code,
            lambda error, status_code=code: (
                render_template(f"errors/{status_code}.html", status_code=status_code),
                status_code,
            ),
        )


def register_commands(app):
    @app.cli.command("seed-demo")
    def seed_demo():
        from datetime import timedelta
        from app.models import Finding, Scan, ScanMetric, utc_now

        user = User.query.filter_by(email="demo@sentinel.local").first()
        if not user:
            user = User(full_name="Demo Analyst", username="demo", email="demo@sentinel.local")
            user.set_password("ChangeMe12345")
            db.session.add(user)
            db.session.flush()

        samples = [
            ("Excellent Example", "https://excellent.test", 96, "Excellent", "passed"),
            ("Good Example", "https://good.test", 84, "Good", "warning"),
            ("Training App", "http://training.local", 61, "Needs Improvement", "failed"),
            ("Legacy Portal", "http://legacy.local", 38, "High Risk", "failed"),
        ]
        for index, (name, url, score, risk, status) in enumerate(samples):
            scan = Scan(
                user_id=user.id,
                scan_name=name,
                target_url=url,
                target_host=url.split("//", 1)[1],
                final_url=url,
                scan_profile="standard",
                status="completed",
                security_score=score,
                risk_level=risk,
                http_status=200,
                response_time=0.2 + index,
                redirect_count=index % 2,
                completed_at=utc_now() - timedelta(days=index),
                duration_seconds=2.4 + index,
            )
            db.session.add(scan)
            db.session.flush()
            finding = Finding(
                scan_id=scan.id,
                category="Demo",
                title=f"Demo {status} finding",
                severity="low" if status != "failed" else "medium",
                status=status,
                description="Sample finding used for local demonstration data.",
                evidence="Demo evidence only.",
                recommendation="Review the corresponding configuration in a real scan.",
                fingerprint=Finding.make_fingerprint("Demo", f"Demo {status} finding", "low"),
            )
            db.session.add(finding)
            db.session.add(ScanMetric(scan_id=scan.id, metric_name="headers_checked", metric_value="9"))
        db.session.commit()
        print("Seeded demo account demo@sentinel.local with password ChangeMe12345")
