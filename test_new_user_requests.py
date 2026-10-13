"""
test_new_user_requests.py
-------------------------
Verifies all 5 user requirements:
1. Vertical Tab Spacing & Styles (.sidebar-nav gap, launchpad CSS)
2. Organization Hub Verification without form redirects
3. Custom Data Classification API (GET /api/classifications, POST /api/classifications)
4. Multi-Role Profiles & Role Switcher (POST /api/users/<id>/roles, POST /api/users/<id>/switch-role)
5. Intent Action Gateway / Launchpad on Home Screen
"""

import unittest
import json
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE, FRONTEND_DIR


class TestNewUserRequests(unittest.TestCase):

    def test_1_css_tab_vertical_spacing(self):
        css_path = os.path.join(FRONTEND_DIR, "styles.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn("gap: 8px;", css, "Sidebar nav should have 8px gap for vertical spacing")
        self.assertIn(".launchpad-banner", css, "Launchpad banner style must exist")
        self.assertIn(".role-switcher-select", css, "Role switcher select style must exist")
        self.assertIn(".custom-classification-badge", css, "Custom classification badge style must exist")
        print("[PASS] 1. CSS Styles: Tab vertical spacing (8px gap) & Launchpad/Role/Custom Classification styles verified.")

    def test_2_html_launchpad_and_org_gate(self):
        html_path = os.path.join(FRONTEND_DIR, "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Intent Launchpad
        self.assertIn("What would you like to do?", html, "Intent Launchpad title must be present")
        self.assertIn("Upload & Encrypt File", html, "Launchpad card 1 must be present")
        self.assertIn("Request Access & Decrypt", html, "Launchpad card 2 must be present")

        # Organization gate form must not submit natively
        self.assertIn('form id="form-org-gate-login" onsubmit="return false;"', html)
        self.assertIn('btn-submit-org-gate-login', html)

        # Multi-role switcher
        self.assertIn('id="active-user-role-select"', html)
        self.assertIn('modal-add-user-role', html)

        # Custom classification
        self.assertIn('modal-custom-classification', html)
        print("[PASS] 2. HTML: Launchpad, non-reloading org gate form, role switcher, and custom classification modal verified.")

    def test_3_custom_classifications_api(self):
        classifications = SERVICE.get_classifications()
        self.assertGreaterEqual(len(classifications), 4, "Should have standard + custom classifications")

        # Create new custom classification
        new_class = SERVICE.add_classification(
            label="DoD Secret Enclave",
            description="Department of Defense level secret technical data",
            color="#ef4444",
            badge_class="badge-coral",
            sensitivity_score=98
        )
        self.assertEqual(new_class["label"], "DoD Secret Enclave")
        self.assertEqual(new_class["sensitivityScore"], 98)

        # Verify it appears in list
        updated_list = SERVICE.get_classifications()
        labels = [c["label"] for c in updated_list]
        self.assertIn("DoD Secret Enclave", labels)
        print("[PASS] 3. API: Custom classifications created, retrieved, and sensitivity scored (98%).")

    def test_4_multi_role_profiles_and_switching(self):
        # User dr_priya has initial roles
        user = SERVICE.get_user("dr_priya")
        self.assertIsNotNone(user)
        self.assertIn("roles", user)
        self.assertIn("Chief Cardiologist", user["roles"])

        # Add new role without creating a new user
        res = SERVICE.add_role_to_user("dr_priya", "Pediatric Surgeon", "Pediatrics")
        self.assertIn("Pediatric Surgeon", res["roles"])
        self.assertIn("Role:Pediatric Surgeon", res["attributes"])
        self.assertIn("Dept:Pediatrics", res["attributes"])

        # Switch active role
        switched = SERVICE.switch_user_role("dr_priya", "Pediatric Surgeon")
        self.assertEqual(switched["activeRole"], "Pediatric Surgeon")
        self.assertEqual(switched["role"], "Pediatric Surgeon")

        # Switch back
        switched_back = SERVICE.switch_user_role("dr_priya", "Chief Cardiologist")
        self.assertEqual(switched_back["activeRole"], "Chief Cardiologist")
        print("[PASS] 4. Multi-Role Profiles: Assigned 'Pediatric Surgeon' to Dr. Priya and switched roles on-the-fly without registering new identity.")

    def test_5_organization_worker_password_auth(self):
        # Metro hospital requires password 'HospitalPass2026!'
        res_ok = SERVICE.verify_worker_credentials("org_hospital", "dr_priya", "HospitalPass2026!")
        self.assertTrue(res_ok["verified"])
        self.assertEqual(res_ok["userId"], "dr_priya")

        # Invalid password rejected
        res_bad = SERVICE.verify_worker_credentials("org_hospital", "dr_priya", "WrongPassword!")
        self.assertFalse(res_bad["verified"])
        print("[PASS] 5. Organization Hub Security: Worker password verified with role boundaries.")

    def test_6_creator_member_whitelist_enforcement(self):
        # 1. Outsider 'alex_architect' is NOT in org_hospital roster
        # Even with the CORRECT password, outsider must be rejected!
        res_outsider = SERVICE.verify_worker_credentials("org_hospital", "alex_architect", "HospitalPass2026!")
        self.assertFalse(res_outsider["verified"], "Outsider must be blocked even with valid password")
        self.assertIn("not an authorized member", res_outsider["error"])

        # 2. Check get_organization_members returns creator flag
        members = SERVICE.get_organization_members("org_hospital")
        priya = next((m for m in members if m["userId"] == "dr_priya"), None)
        self.assertIsNotNone(priya)
        self.assertTrue(priya["isCreator"], "dr_priya must be recognized as creator")

        # 3. Creator whitelists alex_architect
        add_res = SERVICE.add_organization_member("org_hospital", "alex_architect", "Consultant", caller="dr_priya")
        self.assertTrue(add_res["success"])
        self.assertIn("alex_architect", add_res["authorizedMembers"])

        # 4. Now alex_architect can authenticate with password
        res_now_allowed = SERVICE.verify_worker_credentials("org_hospital", "alex_architect", "HospitalPass2026!")
        self.assertTrue(res_now_allowed["verified"], "Newly whitelisted worker must be granted access")

        # 5. Creator revokes alex_architect
        rem_res = SERVICE.remove_organization_member("org_hospital", "alex_architect", caller="dr_priya")
        self.assertTrue(rem_res["success"])
        self.assertNotIn("alex_architect", rem_res["authorizedMembers"])

        # 6. alex_architect blocked again
        res_revoked = SERVICE.verify_worker_credentials("org_hospital", "alex_architect", "HospitalPass2026!")
        self.assertFalse(res_revoked["verified"], "Revoked worker must be blocked again")
        print("[PASS] 6. Creator Whitelist: Strict member enforcement, dynamic whitelisting, and access revocation verified.")


if __name__ == "__main__":
    unittest.main()
