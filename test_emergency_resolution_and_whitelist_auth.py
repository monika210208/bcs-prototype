#!/usr/bin/env python3
"""
Test Suite: Emergency Break-Glass Resolution & Whitelist Authorization Control
Verifies:
1. Only file uploader (owner) and organization creator can whitelist or remove emergency responders.
2. Unauthorized callers attempting whitelist addition/removal receive PermissionError (HTTP 400).
3. Non-whitelisted users are blocked from executing break-glass override.
4. Whitelisted responders can trigger break-glass, activating emergency incidents and temporary on-chain grant.
5. Single emergency incident termination via `/api/emergency/resolve`.
6. Batch emergency incident termination via `/api/emergency/resolve-all`.
7. Resolving an incident revokes the temporary emergency grant and cleans up telemetry/incidents.
8. Frontend UI includes the terminate emergency header button, incident resolution controls, and authorization guards.
"""

import unittest
import os
import sys
import json
import uuid

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import SERVICE, FRONTEND_DIR
from test_handler_mock import execute_request


class TestEmergencyResolutionAndWhitelistAuth(unittest.TestCase):

    def setUp(self):
        # Create a fresh file with unique ID with owner dr_priya in org_hospital (creator: dr_priya)
        fid = f"file_emer_{uuid.uuid4().hex[:8]}"
        upload_res = SERVICE.upload_and_register_file(
            file_id=fid,
            file_name=f"trauma_triage_{fid}.enc",
            description="Critical trauma unit triage asset",
            file_type="Clinical Data",
            owner="dr_priya",
            policy=["Role:Specialist", "Clearance:Level-4"],
            plaintext_bytes=b"PATIENT ALPHA TRIAGE PROTOCOL 2026 TOP SECRET",
            organization_id="org_hospital",
            importance_level="Tier-1 High Enterprise"
        )
        self.file_id = upload_res["fileId"]

    def test_01_whitelist_authorization_backend(self):
        """Unauthorized caller must be rejected when attempting to whitelist or revoke emergency responders."""
        # 1. Random stranger (marcus_legal) is not owner or creator of org_hospital -> Must FAIL
        with self.assertRaises(PermissionError):
            SERVICE.add_file_emergency_whitelist(
                file_id=self.file_id,
                user_id="nurse_arjun",
                caller="marcus_legal"
            )

        # 2. Random stranger attempts to remove -> Must FAIL
        with self.assertRaises(PermissionError):
            SERVICE.remove_file_emergency_whitelist(
                file_id=self.file_id,
                user_id="nurse_arjun",
                caller="marcus_legal"
            )

        # 3. Blank or empty caller -> Must FAIL
        with self.assertRaises(PermissionError):
            SERVICE.add_file_emergency_whitelist(
                file_id=self.file_id,
                user_id="nurse_arjun",
                caller=""
            )

        # 4. File owner (dr_priya) whitelisting nurse_arjun -> Must SUCCEED
        res1 = SERVICE.add_file_emergency_whitelist(
            file_id=self.file_id,
            user_id="nurse_arjun",
            caller="dr_priya"
        )
        self.assertTrue(res1["success"])
        self.assertIn("nurse_arjun", res1["whitelistedResponders"])

        # 5. File owner removing responder -> Must SUCCEED
        res2 = SERVICE.remove_file_emergency_whitelist(
            file_id=self.file_id,
            user_id="nurse_arjun",
            caller="dr_priya"
        )
        self.assertTrue(res2["success"])
        self.assertNotIn("nurse_arjun", res2["whitelistedResponders"])

    def test_02_whitelist_authorization_http(self):
        """HTTP endpoints /api/emergency/whitelist/add and /remove must enforce permissions."""
        # Unauthorized attempt to whitelist by alex_architect on dr_priya's file
        status, _, body = execute_request("POST", "/api/emergency/whitelist/add", {
            "fileId": self.file_id,
            "username": "nurse_arjun",
            "caller": "alex_architect"
        })
        self.assertEqual(status, 400)
        data_fail = json.loads(body.decode("utf-8"))
        self.assertIn("error", data_fail)

        # Authorized attempt by owner (dr_priya)
        status, _, body = execute_request("POST", "/api/emergency/whitelist/add", {
            "fileId": self.file_id,
            "username": "nurse_arjun",
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)
        data_ok = json.loads(body.decode("utf-8"))
        self.assertTrue(data_ok["success"])
        self.assertIn("nurse_arjun", data_ok["whitelistedResponders"])

        # Unauthorized attempt to remove by unauthorized user
        status, _, body = execute_request("POST", "/api/emergency/whitelist/remove", {
            "fileId": self.file_id,
            "username": "nurse_arjun",
            "caller": "alex_architect"
        })
        self.assertEqual(status, 400)

        # Authorized removal by owner (dr_priya)
        status, _, body = execute_request("POST", "/api/emergency/whitelist/remove", {
            "fileId": self.file_id,
            "username": "nurse_arjun",
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)
        rem_data = json.loads(body.decode("utf-8"))
        self.assertTrue(rem_data["success"])
        self.assertNotIn("nurse_arjun", rem_data["whitelistedResponders"])

    def test_03_break_glass_enforcement_and_individual_resolution(self):
        """Non-whitelisted user cannot trigger break glass; whitelisted can; incident can be resolved."""
        # nurse_arjun is not whitelisted yet -> break-glass must FAIL
        with self.assertRaises(PermissionError):
            SERVICE.emergency_break_glass(
                file_id=self.file_id,
                requester="nurse_arjun",
                incident_id="INC-EMER-991",
                justification="Testing unauthorized break-glass",
                ttl_seconds=900,
                dual_witness="Chief Of Surgery"
            )

        # dr_priya whitelists nurse_arjun
        SERVICE.add_file_emergency_whitelist(self.file_id, "nurse_arjun", caller="dr_priya")

        # nurse_arjun triggers break-glass -> SUCCEEDS
        bg_res = SERVICE.emergency_break_glass(
            file_id=self.file_id,
            requester="nurse_arjun",
            incident_id="INC-EMER-991",
            justification="Critical mass casualty emergency trauma protocol override",
            ttl_seconds=900,
            dual_witness="Chief Of Surgery"
        )
        self.assertTrue(bg_res["granted"])
        self.assertEqual(bg_res["incident"]["incidentId"], "INC-EMER-991")

        # Check emergency status reflects active break-glass
        status_info = SERVICE.get_emergency_status()
        self.assertGreaterEqual(status_info["activeIncidentCount"], 1)

        # Check that nurse_arjun now has decryption access under emergency
        status, _, body = execute_request("POST", f"/api/files/{self.file_id}/decrypt", {
            "userId": "nurse_arjun"
        })
        self.assertEqual(status, 200)
        dec_data = json.loads(body.decode("utf-8"))
        self.assertTrue(dec_data["success"])
        self.assertIn("PATIENT ALPHA TRIAGE PROTOCOL", dec_data["plaintext"])

        # Now TERMINATE the emergency incident via /api/emergency/resolve
        status, _, body = execute_request("POST", "/api/emergency/resolve", {
            "incidentId": "INC-EMER-991",
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)
        res_data = json.loads(body.decode("utf-8"))
        self.assertTrue(res_data["success"])
        self.assertEqual(res_data["status"], "RESOLVED")

        # nurse_arjun's temporary emergency grant is now revoked!
        status, _, body = execute_request("POST", f"/api/files/{self.file_id}/decrypt", {
            "userId": "nurse_arjun"
        })
        dec_revoked = json.loads(body.decode("utf-8"))
        self.assertFalse(dec_revoked.get("success", False))

    def test_04_batch_emergency_resolution_http(self):
        """Batch termination via /api/emergency/resolve-all terminates multiple active overrides."""
        # Whitelist nurse_arjun on self.file_id
        SERVICE.add_file_emergency_whitelist(self.file_id, "nurse_arjun", caller="dr_priya")

        # Trigger break-glass 1
        SERVICE.emergency_break_glass(
            file_id=self.file_id,
            requester="nurse_arjun",
            incident_id="INC-BATCH-1",
            justification="Multi-alarm emergency alpha",
            ttl_seconds=900,
            dual_witness="Director A"
        )

        # Create 2nd file and trigger break glass 2
        fid2 = f"file_emer_{uuid.uuid4().hex[:8]}"
        SERVICE.upload_and_register_file(
            file_id=fid2,
            file_name=f"trauma_triage_{fid2}.enc",
            description="2nd asset",
            file_type="Clinical Data",
            owner="dr_priya",
            policy=["Role:Specialist"],
            plaintext_bytes=b"SECOND PAYLOAD",
            organization_id="org_hospital",
            importance_level="Tier-1 High Enterprise"
        )
        SERVICE.add_file_emergency_whitelist(fid2, "nurse_arjun", caller="dr_priya")
        SERVICE.emergency_break_glass(
            file_id=fid2,
            requester="nurse_arjun",
            incident_id="INC-BATCH-2",
            justification="Multi-alarm emergency beta",
            ttl_seconds=900,
            dual_witness="Director B"
        )

        self.assertGreaterEqual(len(SERVICE.emergency_incidents), 2)

        # Batch terminate all active emergencies via HTTP endpoint
        status, _, body = execute_request("POST", "/api/emergency/resolve-all", {
            "caller": "dr_priya"
        })
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["resolvedCount"], 2)

        # All incidents are cleared and active incident count is 0
        self.assertEqual(len(SERVICE.emergency_incidents), 0)
        self.assertEqual(SERVICE.get_emergency_status()["activeIncidentCount"], 0)

    def test_05_frontend_artifacts_and_controls(self):
        """Frontend HTML & JS must contain emergency termination controls and whitelist permission guards."""
        html_path = os.path.join(FRONTEND_DIR, "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for terminate emergency button in the emergency header banner
        self.assertIn("btn-header-stop-emergency", html)
        self.assertIn("window.resolveAllEmergencies()", html)
        self.assertIn("⏹ Terminate Emergency", html)

        # Check for emergency whitelist permission warning in modal
        self.assertIn("modal-emergency-whitelist-perm-warning", html)

        js_path = os.path.join(FRONTEND_DIR, "app.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        # Check for resolution functions and handlers in app.js
        self.assertIn("window.resolveEmergencyIncident", js)
        self.assertIn("window.resolveAllEmergencies", js)
        self.assertIn("api.post('/emergency/resolve'", js)
        self.assertIn("api.post('/emergency/resolve-all'", js)
        self.assertIn("window.openFileEmergencyWhitelistModal", js)
        self.assertIn("modal-emergency-whitelist-perm-warning", js)
        print("[PASS] All emergency break-glass termination and whitelist authorization controls verified!")


if __name__ == "__main__":
    unittest.main()
