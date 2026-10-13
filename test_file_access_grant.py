"""
test_file_access_grant.py
---------------------------
Verify that:
1. File owner can upload a file and immediately decrypt it (no access denied, no CP-ABE attribute failure).
2. Owner or org creator can grant file access to another username (e.g. nurse_arjun or new user).
3. The granted user can immediately decrypt the file without permission error.
4. Revoking access blocks decryption for that user.
5. Emergency whitelisted users can decrypt under break-glass.
"""

import unittest
import os
import sys
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE


class TestFileAccessGrant(unittest.TestCase):

    def test_owner_and_granted_user_decryption(self):
        # 1. Owner dr_priya uploads a new file with strict policy requiring Specialist and Level-5
        upload_res = SERVICE.upload_and_register_file(
            file_id="file_sec_test_01",
            file_name="top_secret_patient_eval.pdf",
            description="Confidential patient assessment",
            file_type="PDF Document",
            owner="dr_priya",
            policy=["Role:Specialist", "Clearance:Level-5"],
            plaintext_bytes=b"%PDF-1.4 Critical Clinical Assessment plain text payload",
            organization_id="org_hospital",
            importance_level="Tier-1 High Enterprise"
        )
        self.assertTrue(upload_res["success"])
        fid = upload_res["fileId"]

        # Verify authorizedUsers includes owner and creator
        overview = SERVICE.get_file_authorized_users(fid)
        self.assertEqual(overview["owner"], "dr_priya")
        self.assertIn("dr_priya", overview["authorizedUsers"])

        # 2. Owner dr_priya attempts to decrypt directly
        dec_owner = SERVICE.decrypt_file(fid, "dr_priya")
        self.assertTrue(dec_owner["success"], f"Owner failed to decrypt: {dec_owner.get('error')}")
        self.assertIn("Critical Clinical Assessment", dec_owner["plaintext"])

        # 3. User nurse_arjun attempts to decrypt before being granted access
        # nurse_arjun has Role:Nurse, Clearance:Level-2 (policy requires Role:Specialist AND Clearance:Level-5)
        # Should fail access check
        has_access = SERVICE.contract.can_access(fid, "nurse_arjun")
        self.assertFalse(has_access)
        dec_arjun_before = SERVICE.decrypt_file(fid, "nurse_arjun")
        self.assertFalse(dec_arjun_before["success"])
        self.assertIn("Access denied", dec_arjun_before["error"])

        # 4. Owner dr_priya explicitly GRANTS file access to nurse_arjun
        grant_res = SERVICE.grant_file_access(fid, "nurse_arjun", caller="dr_priya")
        self.assertTrue(grant_res["success"])

        # Verify nurse_arjun is now in authorizedUsers
        overview_after = SERVICE.get_file_authorized_users(fid)
        self.assertIn("nurse_arjun", overview_after["authorizedUsers"])

        # 5. nurse_arjun attempts to decrypt now -> must succeed
        dec_arjun = SERVICE.decrypt_file(fid, "nurse_arjun")
        self.assertTrue(dec_arjun["success"], f"Granted user nurse_arjun failed to decrypt: {dec_arjun.get('error')}")
        self.assertIn("Critical Clinical Assessment", dec_arjun["plaintext"])

        # 6. Non-creator/non-owner tries to revoke -> should fail with PermissionError
        with self.assertRaises(PermissionError):
            SERVICE.revoke_file_access(fid, "nurse_arjun", caller="alex_chen")

        # 7. Owner revokes file access for nurse_arjun
        revoke_res = SERVICE.revoke_file_access(fid, "nurse_arjun", caller="dr_priya")
        self.assertTrue(revoke_res["success"])

        # 8. nurse_arjun attempts to decrypt after revocation -> should fail
        dec_arjun_revoked = SERVICE.decrypt_file(fid, "nurse_arjun")
        self.assertFalse(dec_arjun_revoked["success"])
        self.assertIn("Access denied", dec_arjun_revoked["error"])

        # 9. Emergency break-glass whitelist test:
        # dr_priya adds dr_watson to emergency whitelist
        em_res = SERVICE.add_file_emergency_whitelist(fid, "dr_watson", caller="dr_priya")
        self.assertTrue(em_res["success"])

        # dr_watson can now decrypt
        dec_watson = SERVICE.decrypt_file(fid, "dr_watson")
        self.assertTrue(dec_watson["success"], f"Emergency whitelisted dr_watson failed: {dec_watson.get('error')}")
        self.assertIn("Critical Clinical Assessment", dec_watson["plaintext"])

    def test_http_api_endpoints_for_file_access(self):
        from test_handler_mock import execute_request

        # 1. dr_priya uploads a new test file via API
        status, _, body = execute_request("POST", "/api/files/upload", {
            "fileName": "http_api_medical_scan.pdf",
            "description": "Scan uploaded for HTTP test",
            "fileType": "DICOM",
            "owner": "dr_priya",
            "organizationId": "org_hospital",
            "policy": ["Role:Director", "Clearance:Level-5"],
            "content": "CONFIDENTIAL CLINICAL SCAN DATA - HTTP ENDPOINT TEST",
            "importance": "Tier-1 High Enterprise"
        })
        self.assertEqual(status, 201)
        up_data = json.loads(body.decode("utf-8"))
        fid = up_data["fileId"]

        # 2. dr_priya (owner) can decrypt immediately via HTTP
        status, _, body = execute_request("POST", f"/api/files/{fid}/decrypt", {
            "userId": "dr_priya"
        })
        self.assertEqual(status, 200)
        dec_data = json.loads(body.decode("utf-8"))
        self.assertTrue(dec_data["success"])
        self.assertIn("CONFIDENTIAL CLINICAL SCAN DATA", dec_data["plaintext"])

        # 3. GET /api/files/:id/authorized-users
        status, _, body = execute_request("GET", f"/api/files/{fid}/authorized-users")
        self.assertEqual(status, 200)
        auth_data = json.loads(body.decode("utf-8"))
        self.assertEqual(auth_data["owner"], "dr_priya")
        self.assertIn("dr_priya", auth_data["authorizedUsers"])

        # 4. alex_chen (Finance Analyst, Level-3) attempts to decrypt -> should fail
        status, _, body = execute_request("POST", f"/api/files/{fid}/decrypt", {
            "userId": "alex_chen"
        })
        dec_alex = json.loads(body.decode("utf-8"))
        self.assertFalse(dec_alex.get("success", False))

        # 5. POST /api/files/:id/grant-user by dr_priya granting alex_chen
        status, _, body = execute_request("POST", f"/api/files/{fid}/grant-user", {
            "userId": "alex_chen",
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)
        grant_resp = json.loads(body.decode("utf-8"))
        self.assertTrue(grant_resp["success"])

        # 6. alex_chen can now decrypt via HTTP
        status, _, body = execute_request("POST", f"/api/files/{fid}/decrypt", {
            "userId": "alex_chen"
        })
        self.assertEqual(status, 200)
        dec_alex2 = json.loads(body.decode("utf-8"))
        self.assertTrue(dec_alex2["success"])
        self.assertIn("CONFIDENTIAL CLINICAL SCAN DATA", dec_alex2["plaintext"])

        # 7. POST /api/files/:id/revoke-user by dr_priya revoking alex_chen
        status, _, body = execute_request("POST", f"/api/files/{fid}/revoke-user", {
            "userId": "alex_chen",
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)

        # 8. alex_chen attempts to decrypt again -> fails
        status, _, body = execute_request("POST", f"/api/files/{fid}/decrypt", {
            "userId": "alex_chen"
        })
        dec_alex3 = json.loads(body.decode("utf-8"))
        self.assertFalse(dec_alex3.get("success", False))

        print("[PASS] HTTP API endpoints for file access grant/revoke and decryption fully verified!")


if __name__ == "__main__":
    unittest.main()
