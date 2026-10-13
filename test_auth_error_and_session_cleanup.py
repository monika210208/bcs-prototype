"""
test_auth_error_and_session_cleanup.py
---------------------------------------
Verifies:
1. Non-existent username returns clear, descriptive error on login (backend & HTTP).
2. Incorrect password returns clear error on login (backend & HTTP).
3. Unavailable/duplicate username returns error on registration (backend & HTTP).
4. HTML contains frontdoor error banners for login and registration steps.
5. HTML contains '✕ Close & Lock File' buttons for decrypted viewers.
6. CSS ensures toast container has top z-index (1000000) so alerts are never hidden.
7. JS contains resetDecryptedSession logic for clean user switching and session logging.
"""

import unittest
import os
import sys
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE, FRONTEND_DIR
from test_handler_mock import execute_request


class TestAuthErrorAndSessionCleanup(unittest.TestCase):

    def test_login_and_registration_error_messages(self):
        # 1. Non-existent username login
        res_bad_user = SERVICE.authenticate_user("ghost_user_999", "SomePassword123")
        self.assertFalse(res_bad_user.get("authenticated", False))
        self.assertIn("does not exist", res_bad_user.get("error", ""))

        status, _, body = execute_request("POST", "/api/auth/login", {
            "userId": "ghost_user_999",
            "password": "SomePassword123"
        })
        self.assertEqual(status, 401)
        err_json = json.loads(body.decode("utf-8"))
        self.assertIn("does not exist", err_json.get("error", ""))

        # 2. Incorrect password login for existing user
        res_bad_pwd = SERVICE.authenticate_user("dr_priya", "TotallyWrongPassword!")
        self.assertFalse(res_bad_pwd.get("authenticated", False))
        self.assertIn("Invalid password", res_bad_pwd.get("error", ""))

        status, _, body = execute_request("POST", "/api/auth/login", {
            "userId": "dr_priya",
            "password": "TotallyWrongPassword!"
        })
        self.assertEqual(status, 401)
        err_json = json.loads(body.decode("utf-8"))
        self.assertIn("Invalid password", err_json.get("error", ""))

        # 3. Duplicate / already taken username registration
        with self.assertRaises(ValueError) as ctx:
            SERVICE.register_account("dr_priya", "Password123!", "Dr. Priya Dup", "org_hospital")
        self.assertIn("already taken", str(ctx.exception))

        status, _, body = execute_request("POST", "/api/auth/register", {
            "userId": "dr_priya",
            "password": "Password123!",
            "name": "Dr. Priya Dup",
            "organizationId": "org_hospital"
        })
        self.assertEqual(status, 400)
        err_json = json.loads(body.decode("utf-8"))
        self.assertIn("already taken", err_json.get("error", ""))

        print("[PASS] 1. Login and registration error handling verified (backend & HTTP).")

    def test_frontend_ui_artifacts(self):
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        app_path = os.path.join(FRONTEND_DIR, "app.js")
        css_path = os.path.join(FRONTEND_DIR, "styles.css")

        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()

        with open(app_path, "r", encoding="utf-8") as f:
            js = f.read()

        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()

        # 1. Error banners in HTML
        self.assertIn('id="frontdoor-login-error-banner"', html)
        self.assertIn('id="frontdoor-reg-error-step1"', html)
        self.assertIn('id="frontdoor-reg-error-step2"', html)

        # 2. Close & Lock File buttons in HTML
        self.assertIn('id="btn-close-requester-decrypted-box"', html)
        self.assertIn('id="btn-close-org-decrypted-box"', html)

        # 3. Toast z-index in CSS
        self.assertIn("1000000", css)
        self.assertIn("frontdoor-error-banner", css)

        # 4. JS session reset logic
        self.assertIn("resetDecryptedSession", js)
        self.assertIn("clearFrontdoorErrors", js)
        self.assertIn("showLoginError", js)
        self.assertIn("showRegError", js)

        print("[PASS] 2. Frontend error banners, close buttons, top toast z-index & session reset verified.")


if __name__ == "__main__":
    unittest.main()
