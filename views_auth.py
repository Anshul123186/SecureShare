from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_limiter.util import get_remote_address

from extensions import db, limiter
from models import User
from security import hash_password, verify_password
from audit import log_event


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password")],
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Login")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("files.dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data.lower()).first()
        if existing:
            flash("Email is already registered.", "warning")
            return redirect(url_for("auth.login"))

        user = User(
            email=form.email.data.lower(),
            password_hash=hash_password(form.password.data),
        )
        db.session.add(user)
        db.session.commit()
        log_event("register", f"User registered: {user.email}", user=user)
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", key_func=get_remote_address)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("files.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not verify_password(form.password.data, user.password_hash):
            log_event("login_failed", f"Failed login for {form.email.data}")
            flash("Invalid credentials.", "danger")
        else:
            login_user(user, remember=form.remember.data)
            log_event("login_success", f"User logged in: {user.email}", user=user)
            next_url = request.args.get("next") or url_for("files.dashboard")
            return redirect(next_url)

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    log_event("logout", f"User logged out: {current_user.email}", user=current_user)
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))

