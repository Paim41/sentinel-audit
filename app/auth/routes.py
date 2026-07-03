from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from sqlalchemy import or_

from app.extensions import db
from app.forms import LoginForm, RegisterForm
from app.models import User


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter(
            or_(User.username == form.username.data.strip(), User.email == form.email.data.lower().strip())
        ).first()
        if existing:
            flash("An account with that username or email already exists.", "warning")
        else:
            user = User(
                full_name=form.full_name.data.strip(),
                username=form.username.data.strip(),
                email=form.email.data.lower().strip(),
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Your account has been created. Please sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form, title="Register")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.lower().strip()
        user = User.query.filter(or_(User.email == identifier, User.username == identifier)).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Signed in successfully.", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))
        flash("Invalid email, username, or password.", "danger")
    return render_template("auth/login.html", form=form, title="Login")


@auth_bp.route("/logout")
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
