"""Tests for the password reset feature.

Run with:  python -m unittest tests.test_password_reset -v

A small in-memory fake replaces MySQL so the tests need no database.
"""
import email
import logging
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from app.auth import password_reset as pr


# ----------------------------------------------------------------- fake DB
class FakeCursor:
    def __init__(self, users):
        self.users = users
        self._result = None
        self.rowcount = 0

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.rowcount = 0
        if sql.startswith("SELECT id, name FROM USERS WHERE LOWER(email)"):
            u = next((u for u in self.users if u["email"].lower() == params[0]), None)
            self._result = (u["id"], u["name"]) if u else None
        elif sql.startswith("SELECT id, reset_token FROM USERS WHERE reset_token"):
            u = next((u for u in self.users if u["reset_token"] == params[0]), None)
            self._result = (u["id"], u["reset_token"]) if u else None
        elif sql.startswith("UPDATE USERS SET reset_token = %s WHERE id = %s"):
            for u in self.users:
                if u["id"] == params[1]:
                    u["reset_token"] = params[0]
                    self.rowcount = 1
        elif sql.startswith("UPDATE USERS SET password_hash = %s, reset_token = NULL"):
            for u in self.users:
                if u["id"] == params[1] and u["reset_token"] == params[2]:
                    u["password_hash"] = params[0]
                    u["reset_token"] = None
                    self.rowcount = 1
        else:
            raise AssertionError(f"Unexpected SQL: {sql}")

    def fetchone(self):
        return self._result

    def close(self):
        pass


class FakeConnection:
    def __init__(self, users):
        self.users = users

    def cursor(self):
        return FakeCursor(self.users)

    def commit(self):
        pass

    def close(self):
        pass


# ------------------------------------------------------------------ tests
class PasswordResetTests(unittest.TestCase):
    OLD_PASSWORD = "password123"
    NEW_PASSWORD = "NewSecret456"

    def setUp(self):
        self.instance_dir = tempfile.mkdtemp()
        self.app = create_app()
        self.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.app.instance_path = self.instance_dir
        self.users = [{
            "id": 1, "name": "Test User", "email": "test@example.com",
            "password_hash": generate_password_hash(self.OLD_PASSWORD),
            "reset_token": None,
        }]
        self.app.get_db_connection = lambda: FakeConnection(self.users)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.instance_dir, ignore_errors=True)

    # helpers
    def outbox(self):
        folder = Path(self.instance_dir) / "mail_outbox"
        return sorted(folder.glob("*.eml")) if folder.exists() else []

    def request_link(self, address="test@example.com"):
        return self.client.post("/forgot-password", data={"email": address})

    def latest_link_path(self):
        msg = email.message_from_bytes(self.outbox()[-1].read_bytes())
        body = msg.get_payload(decode=True).decode()
        return re.search(r"http://localhost(/reset-password/\S+)", body).group(1)

    def reset(self, link_path, password=None, confirm=None):
        password = password or self.NEW_PASSWORD
        self.client.get(link_path)
        return self.client.post("/reset-password", data={
            "password": password, "confirm_password": confirm or password})

    # checklist: neutral response
    def test_response_does_not_reveal_if_email_exists(self):
        known = self.request_link("test@example.com").get_data(as_text=True)
        unknown = self.request_link("nobody@example.com").get_data(as_text=True)
        self.assertEqual(known, unknown)
        self.assertIn("If an account exists", known)
        self.assertEqual(len(self.outbox()), 1)  # only the real user got an email

    # checklist: email generated
    def test_reset_email_is_generated(self):
        self.request_link()
        self.assertEqual(len(self.outbox()), 1)
        self.assertIn("/reset-password/", self.latest_link_path())

    # checklist: change password, new works, old fails, stored hashed
    def test_valid_link_changes_password_and_it_is_hashed(self):
        self.request_link()
        resp = self.reset(self.latest_link_path())
        self.assertIn("Your password has been reset", resp.get_data(as_text=True))
        stored = self.users[0]["password_hash"]
        self.assertNotEqual(stored, self.NEW_PASSWORD)
        self.assertTrue(check_password_hash(stored, self.NEW_PASSWORD))
        self.assertFalse(check_password_hash(stored, self.OLD_PASSWORD))

    def test_only_token_hash_is_stored(self):
        self.request_link()
        raw = self.latest_link_path().rsplit("/", 1)[1]
        self.assertNotEqual(self.users[0]["reset_token"], raw)
        self.assertEqual(self.users[0]["reset_token"], pr._hash_token(raw))

    # checklist: reused token
    def test_reused_token_is_rejected(self):
        self.request_link()
        link = self.latest_link_path()
        self.reset(link)
        resp = self.reset(link, password="Another789x")
        self.assertIn("invalid, has expired, or has already been used",
                      resp.get_data(as_text=True))
        self.assertTrue(check_password_hash(self.users[0]["password_hash"], self.NEW_PASSWORD))

    # checklist: invalid token
    def test_invalid_token_is_rejected(self):
        self.request_link()
        resp = self.reset("/reset-password/not-a-real-token")
        self.assertIn("invalid", resp.get_data(as_text=True))
        self.assertTrue(check_password_hash(self.users[0]["password_hash"], self.OLD_PASSWORD))

    # checklist: expired token
    def test_expired_token_is_rejected(self):
        self.request_link()
        link = self.latest_link_path()
        real_time = time.time
        with mock.patch("itsdangerous.timed.time.time",
                        side_effect=lambda: real_time() + pr.DEFAULT_MAX_AGE_SECONDS + 60):
            resp = self.reset(link)
        self.assertIn("expired", resp.get_data(as_text=True))
        self.assertTrue(check_password_hash(self.users[0]["password_hash"], self.OLD_PASSWORD))

    def test_requesting_new_link_invalidates_old_one(self):
        self.request_link()
        old = self.latest_link_path()
        time.sleep(1.1)  # make sure the second token differs in timestamp too
        self.request_link()
        resp = self.reset(old)
        self.assertIn("invalid", resp.get_data(as_text=True))

    # validation
    def test_password_rules_and_mismatch(self):
        self.request_link()
        link = self.latest_link_path()
        resp = self.reset(link, password="short", confirm="short")
        self.assertIn("at least 8 characters", resp.get_data(as_text=True))
        resp = self.reset(link, password="LongEnough1", confirm="Different1")
        self.assertIn("Passwords do not match", resp.get_data(as_text=True))
        # token is still usable after failed validation
        self.assertIn("Your password has been reset",
                      self.reset(link).get_data(as_text=True))

    # checklist: token not in URL bar after opening the link / not in logs
    def test_link_redirects_to_clean_url(self):
        self.request_link()
        resp = self.client.get(self.latest_link_path())
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/reset-password"))
        self.assertEqual(resp.headers["Referrer-Policy"], "no-referrer")

    def test_access_log_redacts_token(self):
        f = pr._RedactResetTokenFilter()
        rec = logging.LogRecord("werkzeug", logging.INFO, "", 0, '%s - - "%s" %s',
                                ("127.0.0.1", "GET /reset-password/abc.def.ghi HTTP/1.1", "302"), None)
        f.filter(rec)
        self.assertNotIn("abc.def.ghi", rec.getMessage())
        self.assertIn("[REDACTED]", rec.getMessage())


if __name__ == "__main__":
    unittest.main()
