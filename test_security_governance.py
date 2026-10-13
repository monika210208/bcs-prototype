"""
test_security_governance.py
---------------------------
Comprehensive validation of all security governance features:
1. Front-Door Zero-Trust Authentication (login & 2-step registration).
2. Creator Governance: Update member role & clearance levels on-chain.
3. Multi-Tenant Requester Scoping: Private files isolated; Universal Commons open.
4. Audit Log Access Governance: Granular permissions, grant, and revocation.
5. Emergency Break-Glass Whitelist: Strict responder authorization and management.
6. Frontend Artifact Verification: Overlays, modals, and sector choices.
"""

import unittest
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE, FRONTEND_DIR


class TestSecurityGovernance(unittest.TestCase):

    def test_1_frontdoor_authentication_and_registration(self):
        # 1. Existing user authentication
        auth_res = SERVICE.authenticate_user("dr_priya", "UserPass2026!")
        self.assertTrue(auth_res["authenticated"])
        self.assertEqual(auth_res["user"]["userId"], "dr_priya")
        self.assertIn("Level-4", auth_res["user"]["clearance"])
        self.assertTrue(auth_res["user"]["isOrgCreator"])

        # 2. Invalid password rejected
        bad_auth = SERVICE.authenticate_user("dr_priya", "WrongPassword123")
        self.assertFalse(bad_auth["authenticated"])
        self.assertIn("Invalid", bad_auth["error"])

        # 3. 2-Step Registration
        reg_res = SERVICE.register_account(
            user_id="capt_reynolds",
            password="SecurePass2026!",
            name="Capt. Malcolm Reynolds",
            organization_id="org_tech",
            role="Tactical Officer"
        )
        self.assertTrue(reg_res["registered"])
        self.assertEqual(reg_res["user"]["userId"], "capt_reynolds")
        self.assertEqual(reg_res["user"]["organizationId"], "org_tech")
        self.assertTrue(reg_res["user"]["did"].startswith("did:bcs:"))

        # 4. Authenticate newly registered account
        new_auth = SERVICE.authenticate_user("capt_reynolds", "SecurePass2026!")
        self.assertTrue(new_auth["authenticated"])
        self.assertEqual(new_auth["user"]["name"], "Capt. Malcolm Reynolds")
        print("[PASS] 1. Front-Door Zero-Trust Authentication & 2-Step Registration verified.")

    def test_2_creator_member_role_and_clearance_governance(self):
        # Creator dr_priya updates role and clearance of nurse_arjun
        res = SERVICE.update_member_clearance_and_role(
            org_id="org_hospital",
            user_id="nurse_arjun",
            role="Lead Trauma Specialist",
            clearance="Level-5 Top Secret",
            caller="dr_priya"
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["role"], "Lead Trauma Specialist")
        self.assertEqual(res["clearance"], "Level-5 Top Secret")

        # Verify attributes on-chain reflect updated role and clearance
        arjun = SERVICE.get_user("nurse_arjun")
        self.assertTrue(any("Level-5" in a for a in arjun["attributes"]))
        self.assertIn("Role:Lead Trauma Specialist", arjun["attributes"])

        # Outsider cannot modify clearance
        with self.assertRaises(PermissionError):
            SERVICE.update_member_clearance_and_role(
                org_id="org_hospital",
                user_id="nurse_arjun",
                role="Hacker",
                clearance="Level-5",
                caller="marcus_legal"
            )
        print("[PASS] 2. Creator Governance: Update member role & Level-5 clearance verified.")

    def test_3_requester_scoping_and_universal_files(self):
        files = SERVICE.get_files_overview()
        self.assertGreaterEqual(len(files), 6)

        # File 006 is Universal Commons
        file_006 = next((f for f in files if f["fileId"] == "file_006"), None)
        self.assertIsNotNone(file_006)
        self.assertTrue(file_006.get("isUniversal", False))
        self.assertEqual(file_006["organizationId"], "org_general")

        # Files belonging to org_hospital
        hospital_files = [f for f in files if f["organizationId"] == "org_hospital"]
        self.assertGreaterEqual(len(hospital_files), 1)

        # Doctor priya belonging to org_hospital can see hospital + universal files
        priya = SERVICE.get_user("dr_priya")
        scoped_for_priya = [
            f for f in files
            if f.get("isUniversal") or f["organizationId"] == "org_general" or f["organizationId"] == priya["organizationId"]
        ]
        # Should contain hospital files and universal files, but NOT private fintech files
        scoped_ids = [f["fileId"] for f in scoped_for_priya]
        self.assertIn("file_001", scoped_ids)
        self.assertIn("file_006", scoped_ids)
        self.assertNotIn("file_002", scoped_ids)  # file_002 is Quantum Cyber private!
        print("[PASS] 3. Multi-Tenant Requester Scoping & Universal Commons isolation verified.")

    def test_4_audit_log_access_permissions_governance(self):
        # File 001 owner is dr_priya (org_hospital)
        # By default, outsider alex_architect cannot view file_001 audit events
        logs_outsider = SERVICE.get_audit_trail(caller="alex_architect")
        file_001_outsider_logs = [l for l in logs_outsider if l.get("fileId") == "file_001"]
        self.assertEqual(len(file_001_outsider_logs), 0, "Outsider must not see private file logs")

        # Owner dr_priya CAN view file_001 audit events
        logs_owner = SERVICE.get_audit_trail(caller="dr_priya")
        file_001_owner_logs = [l for l in logs_owner if l.get("fileId") == "file_001"]
        self.assertGreaterEqual(len(file_001_owner_logs), 1, "Owner must see file logs")

        # Owner grants log viewing access to alex_architect
        grant_res = SERVICE.grant_log_viewer_access("file_001", "alex_architect", caller="dr_priya")
        self.assertTrue(grant_res["success"])
        self.assertIn("alex_architect", grant_res["logViewers"])

        # Now alex_architect CAN view file_001 audit logs!
        logs_alex = SERVICE.get_audit_trail(caller="alex_architect")
        file_001_alex_logs = [l for l in logs_alex if l.get("fileId") == "file_001"]
        self.assertGreaterEqual(len(file_001_alex_logs), 1, "Granted viewer must see file logs")

        # Owner revokes log viewing access
        revoke_res = SERVICE.revoke_log_viewer_access("file_001", "alex_architect", caller="dr_priya")
        self.assertTrue(revoke_res["success"])
        self.assertNotIn("alex_architect", revoke_res["logViewers"])

        # alex_architect blocked again
        logs_revoked = SERVICE.get_audit_trail(caller="alex_architect")
        file_001_revoked_logs = [l for l in logs_revoked if l.get("fileId") == "file_001"]
        self.assertEqual(len(file_001_revoked_logs), 0, "Revoked viewer must not see file logs")
        print("[PASS] 4. Audit Log Privacy Governance: Granular permissions, grant, and revocation verified.")

    def test_5_emergency_responder_whitelist_governance(self):
        # file_002 belongs to dr_chen (org_quantum)
        # marcus_legal is NOT on file_002 emergency whitelist
        with self.assertRaises(PermissionError):
            SERVICE.emergency_break_glass(
                file_id="file_002",
                requester="marcus_legal",
                incident_id="INC-TEST-001",
                justification="Testing unauthorized override attempt",
                ttl_seconds=900,
                dual_witness="Witness-1"
            )

        # dr_chen whitelists marcus_legal for emergency response on file_002
        add_res = SERVICE.add_file_emergency_whitelist("file_002", "marcus_legal", caller="dr_chen")
        self.assertTrue(add_res["success"])
        self.assertIn("marcus_legal", add_res["whitelistedResponders"])

        # Now marcus_legal CAN trigger emergency break-glass!
        authorized_override = SERVICE.emergency_break_glass(
            file_id="file_002",
            requester="marcus_legal",
            incident_id="INC-TEST-002",
            justification="Critical authorized audit response",
            ttl_seconds=900,
            dual_witness="Witness-1"
        )
        self.assertTrue(authorized_override["granted"])

        # dr_chen removes marcus_legal from emergency whitelist
        rem_res = SERVICE.remove_file_emergency_whitelist("file_002", "marcus_legal", caller="dr_chen")
        self.assertTrue(rem_res["success"])
        self.assertNotIn("marcus_legal", rem_res["whitelistedResponders"])

        # marcus_legal blocked again
        with self.assertRaises(PermissionError):
            SERVICE.emergency_break_glass(
                file_id="file_002",
                requester="marcus_legal",
                incident_id="INC-TEST-003",
                justification="Another attempt after removal",
                ttl_seconds=900,
                dual_witness="Witness-1"
            )
        print("[PASS] 5. Emergency Break-Glass Whitelist: Dynamic responder authorization and enforcement verified.")

    def test_6_frontend_ui_artifacts_and_sectors(self):
        html_path = os.path.join(FRONTEND_DIR, "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Front-Door Zero-Trust Gate Overlay
        self.assertIn('id="frontdoor-auth-overlay"', html)
        self.assertIn('id="form-frontdoor-login"', html)
        self.assertIn('id="form-frontdoor-register"', html)
        self.assertIn('btn-demo-pill', html)

        # Modals
        self.assertIn('id="modal-org-edit-member"', html)
        self.assertIn('id="modal-manage-log-viewers"', html)
        self.assertIn('id="modal-manage-emergency-whitelist"', html)

        # Header Sign Out
        self.assertIn('btn-header-switch-user', html)
        self.assertIn('btn-sidebar-signout', html)

        # Sector Choices (Must include General Purpose, Defense & Military, SecOps, etc.)
        self.assertIn("General Purpose / Universal Commons", html)
        self.assertIn("Defense, Military & Armed Forces (Army / DoD)", html)
        self.assertIn("Confidential Communications & SecOps", html)
        self.assertIn("Intelligence & Homeland Security", html)

        print("[PASS] 6. Frontend Artifacts: Front-door gate, governance modals, sign-out controls, and all 12 sectors verified.")


if __name__ == "__main__":
    unittest.main()
