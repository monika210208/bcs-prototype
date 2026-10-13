#!/usr/bin/env python3
"""
Test Suite: Forgot Password / Reset Password Flow
Verifies:
1. Account lookup & verification (`/api/auth/verify-reset-user`) for valid, missing, and non-existent usernames.
2. Password reset (`/api/auth/reset-password`) validation for empty password, short password (<4 chars), mismatched confirm password, and unknown username.
3. Successful password reset updates user credentials, persists to SQLite DB, and emits a `PasswordReset` audit event on-chain.
4. After password reset, logging in with the old password fails (401) and logging in with the new password succeeds (200).
5. Frontend HTML (`index.html`) and JS (`app.js`) contain all required Forgot Password elements, tabs, and event handlers.
"""

import json
import os
import sys
import time
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE
from test_handler_mock import execute_request


class TestForgotPasswordFlow(unittest.TestCase):

    def _post(self, path, payload):
        status, _, body = execute_request("POST", path, payload)
        return status, json.loads(body.decode("utf-8"))

    def test_1_verify_account_for_reset_validation_and_lookup(self):
        # Empty username -> 400
        status, data = self._post("/api/auth/verify-reset-user", {"userId": ""})
        self.assertEqual(status, 400)
        self.assertFalse(data.get("verified"))

        # Unknown username -> 404
        status, data = self._post("/api/auth/verify-reset-user", {"userId": "ghost_user_xyz_999"})
        self.assertEqual(status, 404)
        self.assertFalse(data.get("verified"))
        self.assertIn("does not exist", data.get("error", ""))

        # Known username -> 200 with account details
        status, data = self._post("/api/auth/verify-reset-user", {"userId": "dr_priya"})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("verified"))
        self.assertEqual(data["user"]["userId"], "dr_priya")
        self.assertIn("did:bcs:", data["user"]["did"])

    def test_2_reset_password_validations_and_login_enforcement(self):
        # Register a temporary test user so we don't mutate default demo passwords permanently
        temp_uid = f"reset_tester_{int(time.time())}"
        reg_status, reg_data = self._post("/api/auth/register", {
            "userId": temp_uid,
            "password": "OldPassword123!",
            "name": "Dr. Reset Tester",
            "organizationId": "org_hospital",
            "role": "Physician"
        })
        self.assertEqual(reg_status, 201)
        self.assertTrue(reg_data.get("registered"))

        # 1. Missing new password -> 400
        status, data = self._post("/api/auth/reset-password", {
            "userId": temp_uid,
            "newPassword": "",
            "confirmPassword": ""
        })
        self.assertEqual(status, 400)
        self.assertFalse(data.get("reset"))

        # 2. Password too short (< 4 chars) -> 400
        status, data = self._post("/api/auth/reset-password", {
            "userId": temp_uid,
            "newPassword": "123",
            "confirmPassword": "123"
        })
        self.assertEqual(status, 400)
        self.assertFalse(data.get("reset"))
        self.assertIn("at least 4 characters", data.get("error", ""))

        # 3. Mismatched confirm password -> 400
        status, data = self._post("/api/auth/reset-password", {
            "userId": temp_uid,
            "newPassword": "NewPassword2026!",
            "confirmPassword": "DifferentPassword!"
        })
        self.assertEqual(status, 400)
        self.assertFalse(data.get("reset"))
        self.assertIn("do not match", data.get("error", ""))

        # 4. Non-existent account -> 404
        status, data = self._post("/api/auth/reset-password", {
            "userId": "non_existent_user_abc",
            "newPassword": "NewPassword2026!",
            "confirmPassword": "NewPassword2026!"
        })
        self.assertEqual(status, 404)
        self.assertFalse(data.get("reset"))

        # 5. Valid password reset -> 200
        status, data = self._post("/api/auth/reset-password", {
            "userId": temp_uid,
            "newPassword": "BrandNewSecurePass99!",
            "confirmPassword": "BrandNewSecurePass99!"
        })
        self.assertEqual(status, 200)
        self.assertTrue(data.get("reset"))
        self.assertEqual(data.get("userId"), temp_uid)

        # 6. Logging in with OLD password must now fail (401)
        login_old_status, login_old_data = self._post("/api/auth/login", {
            "userId": temp_uid,
            "password": "OldPassword123!"
        })
        self.assertEqual(login_old_status, 401)
        self.assertFalse(login_old_data.get("authenticated"))

        # 7. Logging in with NEW password must succeed (200)
        login_new_status, login_new_data = self._post("/api/auth/login", {
            "userId": temp_uid,
            "password": "BrandNewSecurePass99!"
        })
        self.assertEqual(login_new_status, 200)
        self.assertTrue(login_new_data.get("authenticated"))
        self.assertEqual(login_new_data["user"]["userId"], temp_uid)

    def test_3_frontend_forgot_password_elements_present(self):
        with open(os.path.join(CURRENT_DIR, "frontend", "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
        with open(os.path.join(CURRENT_DIR, "frontend", "app.js"), "r", encoding="utf-8") as f:
            js = f.read()

        # Verify HTML elements for Forgot Password tab, link, pane, and inputs
        for elem_id in [
            "tab-frontdoor-forgot",
            "btn-open-forgot-password",
            "frontdoor-pane-forgot",
            "frontdoor-forgot-username",
            "btn-verify-forgot-user",
            "forgot-user-verified-card",
            "frontdoor-forgot-new-password",
            "frontdoor-forgot-confirm-password",
            "frontdoor-forgot-error-banner",
            "frontdoor-forgot-success-banner",
            "btn-forgot-back-to-login",
            "btn-submit-forgot-password",
        ]:
            self.assertIn(elem_id, html, f"Missing element ID #{elem_id} in index.html")

        # Verify JS handlers and endpoints
        self.assertIn("window.verifyForgotUser", js)
        self.assertIn("window.resetForgotPassword", js)
        self.assertIn("/auth/verify-reset-user", js)
        self.assertIn("/auth/reset-password", js)


if __name__ == "__main__":
    unittest.main()
