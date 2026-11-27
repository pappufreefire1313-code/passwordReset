"""
Password reset (Sprint 1 - Pappu Yadav).

Flow
----
1. GET/POST /forgot-password
   User enters an email. We ALWAYS show the same neutral message. If the
   email belongs to a user, a reset link is emailed to them.
2. GET /reset-password/<token>
   The token is checked, moved into the server-side session, and the user
   is redirected to /reset-password so the token leaves the address bar
   (and is not sent on as a Referer).
3. POST /reset-password
   New password is validated, hashed (werkzeug, same as seed_db.py) and
   saved. The token is invalidated so it cannot be reused.

Token design (no schema change needed)
--------------------------------------
* A random 32-byte value (secrets.token_urlsafe) is signed with the app's
  SECRET_KEY + a timestamp using itsdangerous (ships with Flask). The
  signature gives us expiry and tamper detection.
* Only a SHA-256 hash of the signed token is stored in USERS.reset_token.
  The raw token exists only in the email.
* After a successful reset (or when a newer link is requested) the stored
  hash is replaced/cleared, so old and used links stop working.
* The token contains no user id or email, so nothing about the account is
  exposed in the URL.

Coordination notes
------------------
* Uses the existing USERS table (email, password_hash, reset_token).
* Uses werkzeug.security.generate_password_hash, like seed_db.py.
  -> Confirm with Shailesh that login uses check_password_hash.
* _send_email() is a placeholder until Aman's shared email utility exists.
  Swap the body of _send_email() for a call to that utility.
"""

import email.policy
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

from flask import (Blueprint, current_app, redirect, render_template,
                   request, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import generate_password_hash

password_reset_bp = Blueprint("password_reset", __name__)

log = logging.getLogger(__name__)

TOKEN_SALT = "aawazsetu-password-reset"
DEFAULT_MAX_AGE_SECONDS = 30 * 60          # links expire after 30 minutes
MIN_PASSWORD_LENGTH = 8
SESSION_KEY = "pw_reset_token"

NEUTRAL_MESSAGE = (
    "If an account exists for that email address, we have sent a link to "
    "reset your password. The link expires in {minutes} minutes."
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _get_db_connection():
    """Use the shared DB helper (app.db if the team adds it, otherwise the
    one attached to the app in create_app)."""
    try:
        from app.db import get_db_connection  # future shared module
        return get_db_connection()
    except ImportError:
        return current_app.get_db_connection()


def _max_age():
    return int(os.getenv("PASSWORD_RESET_MAX_AGE",
                         current_app.config.get("PASSWORD_RESET_MAX_AGE",
                                                DEFAULT_MAX_AGE_SECONDS)))


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"],
                                  salt=TOKEN_SALT)


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reset_token():
    """Return (raw_token_for_email, hash_for_database)."""
    token = _serializer().dumps(secrets.token_urlsafe(32))
    return token, _hash_token(token)


def token_signature_is_valid(token):
    """True if the token was signed by us and has not expired."""
    try:
        _serializer().loads(token, max_age=_max_age())
        return True
    except (SignatureExpired, BadSignature):
        return False


def _find_user_by_token(cursor, token):
    """Return the user row for a valid, unused token, else None."""
    if not token or not token_signature_is_valid(token):
        return None
    token_hash = _hash_token(token)
    cursor.execute("SELECT id, reset_token FROM USERS WHERE reset_token = %s",
                   (token_hash,))
    row = cursor.fetchone()
    if row and hmac.compare_digest(row[1] or "", token_hash):
        return row
    return None


def validate_new_password(password, confirm):
    """Return a list of error messages (empty list = valid)."""
    errors = []
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if password and not re.search(r"[A-Za-z]", password):
        errors.append("Password must contain at least one letter.")
    if password and not re.search(r"\d", password):
        errors.append("Password must contain at least one number.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


def _mask_email(email):
    name, _, domain = email.partition("@")
    return f"{name[:1]}***@{domain}"


def _send_email(to_address, subject, body):
    """TEMPORARY mail sender - replace with Aman's shared email utility.

    * If MAIL_SERVER is set in .env, sends via SMTP.
    * Otherwise (local testing) writes the email to instance/mail_outbox/
      which is git-ignored. Never prints the link to the console/logs.
    """
    # No line wrapping, so the reset link stays on one line and is easy to copy.
    msg = EmailMessage(policy=email.policy.SMTP.clone(max_line_length=None))
    msg["Subject"] = subject
    msg["From"] = os.getenv("MAIL_DEFAULT_SENDER", "no-reply@aawazsetu.local")
    msg["To"] = to_address
    msg.set_content(body, cte="8bit")

    server = os.getenv("MAIL_SERVER")
    if server:
        port = int(os.getenv("MAIL_PORT", 587))
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            if os.getenv("MAIL_USE_TLS", "true").lower() == "true":
                smtp.starttls()
            user = os.getenv("MAIL_USERNAME")
            if user:
                smtp.login(user, os.getenv("MAIL_PASSWORD", ""))
            smtp.send_message(msg)
    else:
        outbox = Path(current_app.instance_path) / "mail_outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        (outbox / f"{stamp}-password-reset.eml").write_bytes(msg.as_bytes())

    log.info("Password reset email sent to %s", _mask_email(to_address))


def _no_referrer(response):
    """Stop the browser from leaking the reset URL to other sites."""
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@password_reset_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if email:
            conn = cursor = None
            try:
                conn = _get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id, name FROM USERS WHERE LOWER(email) = %s",
                               (email,))
                user = cursor.fetchone()
                if user:
                    token, token_hash = generate_reset_token()
                    # Overwrites any older hash -> older links stop working.
                    cursor.execute("UPDATE USERS SET reset_token = %s WHERE id = %s",
                                   (token_hash, user[0]))
                    conn.commit()
                    link = url_for("password_reset.reset_password_link",
                                   token=token, _external=True)
                    minutes = _max_age() // 60
                    _send_email(
                        email,
                        "Reset your AawazSetu password",
                        f"Hello {user[1]},\n\n"
                        f"We received a request to reset your AawazSetu password.\n"
                        f"Open this link to choose a new password (valid for {minutes} minutes):\n\n"
                        f"{link}\n\n"
                        f"If you did not ask for this, you can ignore this email.\n",
                    )
            except Exception:
                # Log without details that could contain the email/token,
                # and still show the neutral message.
                log.exception("Password reset request failed")
            finally:
                if cursor is not None:
                    cursor.close()
                if conn is not None:
                    conn.close()
        message = NEUTRAL_MESSAGE.format(minutes=_max_age() // 60)

    return render_template("auth/forgot_password.html", message=message)


@password_reset_bp.route("/reset-password/<token>")
def reset_password_link(token):
    """Entry point from the email. Move the token into the session and
    redirect so it is no longer in the URL."""
    session[SESSION_KEY] = token
    return _no_referrer(redirect(url_for("password_reset.reset_password")))


@password_reset_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = session.get(SESSION_KEY)
    conn = cursor = None
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        user = _find_user_by_token(cursor, token)

        if user is None:
            session.pop(SESSION_KEY, None)
            return _no_referrer(current_app.make_response(render_template(
                "auth/reset_result.html", success=False,
                message="This reset link is invalid, has expired, or has already been used. "
                        "Please request a new one.")))

        errors = []
        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            errors = validate_new_password(password, confirm)
            if not errors:
                cursor.execute(
                    "UPDATE USERS SET password_hash = %s, reset_token = NULL "
                    "WHERE id = %s AND reset_token = %s",
                    (generate_password_hash(password), user[0], _hash_token(token)))
                conn.commit()
                session.pop(SESSION_KEY, None)
                if cursor.rowcount == 1:
                    return _no_referrer(current_app.make_response(render_template(
                        "auth/reset_result.html", success=True,
                        message="Your password has been reset. You can now log in with your new password.")))
                return _no_referrer(current_app.make_response(render_template(
                    "auth/reset_result.html", success=False,
                    message="This reset link has already been used. Please request a new one.")))

        return _no_referrer(current_app.make_response(render_template(
            "auth/reset_password.html", errors=errors,
            min_length=MIN_PASSWORD_LENGTH)))

    except Exception:
        log.exception("Password reset failed")
        return render_template(
            "auth/reset_result.html", success=False,
            message="Something went wrong. Please try again later."), 500
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


# --------------------------------------------------------------------------
# Keep tokens out of the Flask dev-server access log
# --------------------------------------------------------------------------
class _RedactResetTokenFilter(logging.Filter):
    _pattern = re.compile(r"(/reset-password/)[^\s?\"]+")

    def filter(self, record):
        try:
            text = record.getMessage()
        except Exception:
            return True
        if "/reset-password/" in text:
            record.msg = self._pattern.sub(r"\1[REDACTED]", text)
            record.args = ()
        return True


def init_password_reset(app):
    """Register the blueprint and the log filter on the app."""
    app.register_blueprint(password_reset_bp)
    logging.getLogger("werkzeug").addFilter(_RedactResetTokenFilter())
