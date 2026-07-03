from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, IntegerField, PasswordField, SelectField, StringField, SubmitField, URLField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional


class RegisterForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=120)])
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=128)])
    confirm_password = PasswordField(
        "Confirm password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    identifier = StringField("Email or username", validators=[DataRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class ScanForm(FlaskForm):
    target_url = URLField("Target URL", validators=[DataRequired(), Length(max=2048)])
    scan_name = StringField("Optional scan name", validators=[Optional(), Length(max=160)])
    scan_profile = SelectField(
        "Scan profile",
        choices=[("quick", "Quick Scan"), ("standard", "Standard Scan")],
        validators=[DataRequired()],
    )
    authorised = BooleanField(
        "I confirm that I own this website or have explicit permission to perform this security audit.",
        validators=[DataRequired()],
    )
    submit = SubmitField("Start Scan")


class SettingsForm(FlaskForm):
    default_scan_profile = SelectField(
        "Default scan profile",
        choices=[("quick", "Quick Scan"), ("standard", "Standard Scan")],
        validators=[DataRequired()],
    )
    request_timeout = IntegerField("Request timeout", validators=[Optional(), NumberRange(min=1, max=60)])
    maximum_redirects = IntegerField("Maximum redirects", validators=[Optional(), NumberRange(min=0, max=10)])
    pdf_preference = SelectField(
        "PDF report preference",
        choices=[("detailed", "Detailed PDF"), ("summary", "Summary PDF")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Save preferences")
