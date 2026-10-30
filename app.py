import pyotp
import qrcode
import io
import base64
import os
import secrets
import time
import hashlib

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from email_validator import validate_email, EmailNotValidError
from flask_mail import Mail, Message


# --------------------------------------------------
# Flask App Configuration
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-key-change-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securegate.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# --------------------------------------------------
# Gmail SMTP Configuration
# --------------------------------------------------

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True

app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")

# Important: Default sender must be configured
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")

mail = Mail(app)


# --------------------------------------------------
# Database, CSRF and Login Manager
# --------------------------------------------------

db = SQLAlchemy(app)

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"


# --------------------------------------------------
# User Model
# --------------------------------------------------

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(254),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    totp_secret = db.Column(
        db.String(64),
        nullable=True
    )

    mfa_enabled = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )


# --------------------------------------------------
# Load User
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --------------------------------------------------
# Home
# --------------------------------------------------

@app.route("/")
def home():
    return redirect(url_for("register"))


# --------------------------------------------------
# Generate Email OTP
# --------------------------------------------------

def generate_email_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


# --------------------------------------------------
# Hash Email OTP
# --------------------------------------------------

def hash_email_otp(otp):
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


# --------------------------------------------------
# Check OTP Expiry
# --------------------------------------------------

def is_otp_valid(created_at):
    return 0 <= time.time() - created_at <= 300


# --------------------------------------------------
# Send OTP Email
# --------------------------------------------------

def send_otp_email(recipient_email, otp):

    try:

        message = Message(
            subject="Your SecureGate Login OTP",

            sender=app.config["MAIL_DEFAULT_SENDER"],

            recipients=[recipient_email],

            body=(
                f"Your SecureGate verification code is: {otp}\n\n"
                "This code is valid for 5 minutes.\n"
                "Do not share this code with anyone."
            )
        )

        mail.send(message)

        app.logger.info(
            "OTP email sent successfully to recipient."
        )

        return True

    except Exception:

        app.logger.exception(
            "Failed to send SecureGate OTP email."
        )

        return False


# --------------------------------------------------
# Register
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # Username validation
        if not username or len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "error"
            )

            return redirect(url_for("register"))

        if len(username) > 80:

            flash(
                "Username is too long.",
                "error"
            )

            return redirect(url_for("register"))

        # Email validation
        try:

            validate_email(
                email,
                check_deliverability=False
            )

        except EmailNotValidError:

            flash(
                "Please enter a valid email address.",
                "error"
            )

            return redirect(url_for("register"))

        # Password validation
        if len(password) < 12:

            flash(
                "Password must contain at least 12 characters.",
                "error"
            )

            return redirect(url_for("register"))

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(url_for("register"))

        # Check duplicate username
        if User.query.filter_by(
            username=username
        ).first():

            flash(
                "Username is already registered.",
                "error"
            )

            return redirect(url_for("register"))

        # Check duplicate email
        if User.query.filter_by(
            email=email
        ).first():

            flash(
                "Email is already registered.",
                "error"
            )

            return redirect(url_for("register"))

        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)

        db.session.commit()

        flash(
            "Registration successful! Your password is securely hashed.",
            "success"
        )

        return redirect(url_for("register"))

    return render_template("register.html")


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        # Check user credentials
        if (
            not user
            or not check_password_hash(
                user.password_hash,
                password
            )
        ):

            flash(
                "Invalid email or password.",
                "error"
            )

            return redirect(url_for("login"))

        # Clear old session data
        session.clear()

        session["pending_user_id"] = user.id

        # If authenticator MFA is enabled
        if user.mfa_enabled:

            return redirect(
                url_for("verify_mfa")
            )

        # Generate email OTP
        otp = generate_email_otp()

        # Send OTP email
        if not send_otp_email(
            user.email,
            otp
        ):

            session.clear()

            flash(
                "Unable to send OTP email. Please try again.",
                "error"
            )

            return redirect(url_for("login"))

        # Save OTP information in session
        session["email_otp_hash"] = hash_email_otp(otp)

        session["email_otp_created_at"] = time.time()

        session["email_otp_attempts"] = 0

        flash(
            "A verification code has been sent to your email.",
            "success"
        )

        return redirect(
            url_for("verify_email_otp")
        )

    return render_template("login.html")


# --------------------------------------------------
# Verify Email OTP
# --------------------------------------------------

@app.route("/verify-email-otp", methods=["GET", "POST"])
def verify_email_otp():

    user_id = session.get(
        "pending_user_id"
    )

    otp_hash = session.get(
        "email_otp_hash"
    )

    created_at = session.get(
        "email_otp_created_at"
    )

    # Check session
    if not user_id or not otp_hash or not created_at:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    # Check OTP expiry
    if not is_otp_valid(created_at):

        session.clear()

        flash(
            "OTP expired. Please log in again.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        entered_otp = request.form.get(
            "code", ""
        ).strip()

        # Validate OTP format
        if (
            not entered_otp.isdigit()
            or len(entered_otp) != 6
        ):

            flash(
                "OTP must be exactly 6 digits.",
                "error"
            )

            return redirect(
                url_for("verify_email_otp")
            )

        attempts = session.get(
            "email_otp_attempts", 0
        )

        # Check attempts
        if attempts >= 5:

            session.clear()

            flash(
                "Too many incorrect attempts. Please log in again.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # Verify OTP
        if secrets.compare_digest(
            hash_email_otp(entered_otp),
            otp_hash
        ):

            user = db.session.get(
                User,
                user_id
            )

            if not user:

                session.clear()

                flash(
                    "User account not found. Please log in again.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )

            # Clear OTP session
            session.clear()

            # Login user
            login_user(user)

            flash(
                "Email verification successful!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        # Incorrect OTP
        session["email_otp_attempts"] = attempts + 1

        flash(
            "Incorrect OTP. Please try again.",
            "error"
        )

        return redirect(
            url_for("verify_email_otp")
        )

    return render_template(
        "email_otp.html"
    )


# --------------------------------------------------
# Setup Authenticator MFA
# --------------------------------------------------

@app.route("/setup-mfa")
@login_required
def setup_mfa():

    if not current_user.totp_secret:

        current_user.totp_secret = pyotp.random_base32()

        db.session.commit()

    totp = pyotp.TOTP(
        current_user.totp_secret
    )

    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecureGate"
    )

    # Generate QR code
    qr = qrcode.make(
        provisioning_uri
    )

    buffer = io.BytesIO()

    qr.save(
        buffer,
        format="PNG"
    )

    qr_image = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    return render_template(
        "setup_mfa.html",
        qr_image=qr_image
    )


# --------------------------------------------------
# Confirm Authenticator MFA
# --------------------------------------------------

@app.route("/confirm-mfa", methods=["POST"])
@login_required
def confirm_mfa():

    code = request.form.get(
        "code", ""
    ).strip()

    # Validate code
    if (
        not code.isdigit()
        or len(code) != 6
    ):

        flash(
            "Verification code must be exactly 6 digits.",
            "error"
        )

        return redirect(
            url_for("setup_mfa")
        )

    if not current_user.totp_secret:

        flash(
            "Please set up your authenticator first.",
            "error"
        )

        return redirect(
            url_for("setup_mfa")
        )

    totp = pyotp.TOTP(
        current_user.totp_secret
    )

    # Verify authenticator code
    if totp.verify(
        code,
        valid_window=1
    ):

        current_user.mfa_enabled = True

        db.session.commit()

        flash(
            "Authenticator MFA enabled successfully!",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    flash(
        "Invalid verification code. Please try again.",
        "error"
    )

    return redirect(
        url_for("setup_mfa")
    )


# --------------------------------------------------
# Verify MFA
# --------------------------------------------------

@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():

    user_id = session.get(
        "pending_user_id"
    )

    if not user_id:

        flash(
            "Please log in first.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        session.clear()

        flash(
            "User account not found. Please log in again.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if not user.mfa_enabled:

        flash(
            "Authenticator MFA is not enabled for this account.",
            "error"
        )

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        method = request.form.get(
            "method", ""
        )

        code = request.form.get(
            "code", ""
        ).strip()

        # Validate code
        if (
            not code.isdigit()
            or len(code) != 6
        ):

            flash(
                "Verification code must be exactly 6 digits.",
                "error"
            )

            return redirect(
                url_for("verify_mfa")
            )

        # Authenticator verification
        if method == "authenticator":

            if not user.totp_secret:

                flash(
                    "Authenticator setup is incomplete. Please set it up again.",
                    "error"
                )

                return redirect(
                    url_for("setup_mfa")
                )

            totp = pyotp.TOTP(
                user.totp_secret
            )

            if totp.verify(
                code,
                valid_window=1
            ):

                session.clear()

                login_user(user)

                flash(
                    "Authenticator verification successful!",
                    "success"
                )

                return redirect(
                    url_for("dashboard")
                )

            flash(
                "Invalid authenticator code.",
                "error"
            )

            return redirect(
                url_for("verify_mfa")
            )

        # Email OTP verification
        if method == "email":

            otp = generate_email_otp()

            if not send_otp_email(
                user.email,
                otp
            ):

                flash(
                    "Unable to send OTP email. Please try again.",
                    "error"
                )

                return redirect(
                    url_for("verify_mfa")
                )

            session["email_otp_hash"] = hash_email_otp(otp)

            session["email_otp_created_at"] = time.time()

            session["email_otp_attempts"] = 0

            flash(
                "A verification code has been sent to your email.",
                "success"
            )

            return redirect(
                url_for("verify_email_otp")
            )

        flash(
            "Please select a valid verification method.",
            "error"
        )

        return redirect(
            url_for("verify_mfa")
        )

    return render_template(
        "mfa_verify.html"
    )


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html"
    )


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    logout_user()

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# Run Application
# --------------------------------------------------

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    app.run(
        debug=True
    )