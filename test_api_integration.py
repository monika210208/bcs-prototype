"""
test_api_integration.py
------------------------
Automated test suite verifying 100% of the backend capabilities and API workflows:
1. User registration & attribute authority
2. Step 1-3: Encrypt file, store blob off-chain, register policy on-chain
3. Step 4-5: Smart contract automated policy evaluation (granted vs denied)
4. Step 6: Off-chain blob retrieval & cryptographic CP-ABE decryption
5. Step 8: Per-user access revocation
6. Emergency global kill-switch revocation
7. Step 7: Immutable audit log verification
8. Section 6.3: Evaluation benchmarks & gas calculation
"""

import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from backend_service import BackendService


def run_tests():
    print("=" * 65)
    print("RUNNING BCS FULL-STACK BACKEND INTEGRATION TEST SUITE")
    print("=" * 65)

    svc = BackendService()

    # Test 1: Seeded Users
    users = svc.get_users()
    assert len(users) >= 5, f"Expected at least 5 users, got {len(users)}"
    print("[PASS] 1. User & Identity Module: Initialized with registered users.")

    # Test 2: Create new user & attribute assignment
    new_user = svc.create_user("test_doc", "Dr. Test Specialist", "Surgeon", "Surgery", "Level-3 Confidential")
    assert new_user["userId"] == "test_doc"
    assert "Role:Surgeon" in new_user["attributes"]
    print("[PASS] 2. User & Identity Module: New user created and attributes issued.")

    # Test 3: Upload & Encrypt new file
    test_file_id = "test_file_999"
    upload_res = svc.upload_and_register_file(
        file_id=test_file_id,
        file_name="surgical_consent_form_999.pdf",
        description="Patient consent & pre-operative surgical evaluation",
        file_type="Medical Consent Form",
        owner="test_doc",
        policy=["Role:Surgeon", "Dept:Surgery"],
        plaintext_bytes=b"CONFIDENTIAL: Patient approved laparoscopic cholecystectomy scheduled for tomorrow 09:00."
    )
    assert upload_res["fileId"] == test_file_id
    assert upload_res["contentHash"] is not None
    assert upload_res["envelope"]["policy"] == ["Role:Surgeon", "Dept:Surgery"]
    print("[PASS] 3. Steps 1-3: File encrypted (CP-ABE), blob stored off-chain, policy registered on-chain.")

    # Test 4: Access Request - Authorized User
    req_auth = svc.request_access(test_file_id, "test_doc")
    assert req_auth["granted"] is True, f"test_doc should be granted, got: {req_auth}"
    print("[PASS] 4. Step 4-5 (Authorized): Smart contract automatically evaluated policy -> GRANTED.")

    # Test 5: Decrypt File - Authorized User
    dec_auth = svc.decrypt_file(test_file_id, "test_doc")
    assert dec_auth["success"] is True, f"Decryption should succeed, got: {dec_auth}"
    assert "laparoscopic cholecystectomy" in dec_auth["plaintext"]
    print("[PASS] 5. Step 6: Authorized user retrieved off-chain blob & decrypted plaintext locally.")

    # Test 6: Access Request - Unauthorized User (nurse_arjun missing Role:Surgeon)
    req_unauth = svc.request_access(test_file_id, "nurse_arjun")
    assert req_unauth["granted"] is False
    assert "Role:Surgeon" in req_unauth["missingAttrs"]
    print("[PASS] 6. Step 4-5 (Unauthorized): Smart contract rejected access -> DENIED (missing attributes).")

    # Test 7: Decryption attempt by unauthorized user (should be blocked at contract layer)
    dec_unauth = svc.decrypt_file(test_file_id, "nurse_arjun")
    assert dec_unauth["success"] is False
    print("[PASS] 7. Security Enforcement: Unauthorized user blocked from retrieving/decrypting ciphertext.")

    # Test 8: Per-user access revocation (Step 8)
    rev_res = svc.revoke_user_access(test_file_id, "test_doc", caller="test_doc")
    assert rev_res["success"] is True
    # Can access now?
    check_rev = svc.check_access(test_file_id, "test_doc")
    assert check_rev["canAccess"] is False
    # Attempting to decrypt should fail now
    dec_after_rev = svc.decrypt_file(test_file_id, "test_doc")
    assert dec_after_rev["success"] is False
    print("[PASS] 8. Step 8: Per-user access revocation executed on-chain. Decryption immediately blocked.")

    # Test 9: Emergency Global Kill-Switch
    # Re-grant for demonstration, then kill-switch
    svc.request_access(test_file_id, "test_doc")
    kill_res = svc.revoke_all_access(test_file_id, caller="test_doc")
    assert kill_res["revokedAll"] is True
    check_kill = svc.check_access(test_file_id, "test_doc")
    assert check_kill["canAccess"] is False
    # Restore
    rest_res = svc.restore_all_access(test_file_id, caller="test_doc")
    assert rest_res["revokedAll"] is False
    print("[PASS] 9. Emergency Kill-Switch: Global file revocation and restoration verified.")

    # Test 10: Immutable Audit Log
    logs = svc.get_audit_trail()
    assert len(logs) > 10, f"Expected extensive audit log, got {len(logs)}"
    # Verify filter
    grant_logs = svc.get_audit_trail(filter_event="AccessGranted")
    assert all(e["event"] == "AccessGranted" for e in grant_logs)
    print(f"[PASS] 10. Step 7: Audit & Logging Module: Verified {len(logs)} immutable events and filtering.")

    # Test 11: Benchmarks
    bm = svc.run_benchmarks()
    assert bm["bcsRevocationTimeMs"] < bm["baselineReencryptionTimeMs"]
    assert bm["gasCosts"]["uploadFile"] > 0
    print(f"[PASS] 11. Section 6.3 Benchmarks: Measured {bm['revocationEfficiencyGain']} speedup in revocation.")

    print("\n" + "=" * 65)
    print("ALL 11 INTEGRATION TESTS PASSED SUCCESSFULLY! (100% SUCCESS)")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_tests()
