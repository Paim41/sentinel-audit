from app import create_app
from app.extensions import db
from app.models import Scan, User, utc_now


def make_user(email, username):
    user = User(full_name="Test User", username=username, email=email)
    user.set_password("StrongPassword123")
    db.session.add(user)
    db.session.commit()
    return user


def login(client, identifier="one@example.com"):
    return client.post(
        "/auth/login",
        data={"identifier": identifier, "password": "StrongPassword123"},
        follow_redirects=True,
    )


def test_database_creation():
    app = create_app("testing")
    with app.app_context():
        assert db.engine is not None
        assert User.query.count() == 0


def test_authentication_protection():
    app = create_app("testing")
    client = app.test_client()
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_scan_ownership_enforced():
    app = create_app("testing")
    client = app.test_client()
    with app.app_context():
        one = make_user("one@example.com", "one")
        two = make_user("two@example.com", "two")
        scan = Scan(
            user_id=two.id,
            scan_name="Other scan",
            target_url="https://example.com",
            target_host="example.com",
            final_url="https://example.com",
            scan_profile="quick",
            status="completed",
            security_score=90,
            risk_level="Excellent",
            started_at=utc_now(),
            completed_at=utc_now(),
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id
    login(client)
    response = client.get(f"/scans/{scan_id}")
    assert response.status_code == 403
