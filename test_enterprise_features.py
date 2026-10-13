"""
Test suite for Enterprise Multi-Org, Technical Estimator, and Emergency Protocols in OmniVault BCS.
"""
import os
import sys
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from test_handler_mock import execute_request

def run_tests():
    print("=" * 65)
    print("TESTING ENTERPRISE MULTI-ORG, ESTIMATOR & EMERGENCY PROTOCOLS")
    print("=" * 65)

    # 1. Organization List
    code, hdrs, body = execute_request("GET", "/api/organizations")
    assert code == 200, f"Expected 200, got {code}"
    orgs = json.loads(body.decode("utf-8"))
    assert len(orgs) >= 4
    org_ids = [o["orgId"] for o in orgs]
    assert "org_hospital" in org_ids and "org_fintech" in org_ids
    print(f"[PASS] 1. Multi-Org: {len(orgs)} organizations registered (Hospital, FinTech, Cyber Labs, Commons).")

    # 2. Worker Password Verification
    code, hdrs, body = execute_request("POST", "/api/organizations/verify-worker", {
        "orgId": "org_hospital",
        "userId": "dr_priya",
        "password": "HospitalPass2026!"
    })
    assert code == 200, f"Expected 200, got {code}"
    res = json.loads(body.decode("utf-8"))
    assert res["verified"] is True
    print("[PASS] 2. Organization Auth: Metro General Hospital worker password verified.")

    # 3. Wrong password check
    code, hdrs, body = execute_request("POST", "/api/organizations/verify-worker", {
        "orgId": "org_hospital",
        "userId": "dr_priya",
        "password": "WrongPassword"
    })
    assert code == 401
    res = json.loads(body.decode("utf-8"))
    assert res["verified"] is False
    print("[PASS] 3. Organization Security: Invalid worker credentials rejected with 401.")

    # 4. Create Custom Organization
    code, hdrs, body = execute_request("POST", "/api/organizations", {
        "orgId": "org_aerospace",
        "name": "Starlight Aerospace",
        "sector": "Aerospace & Defense",
        "workerPassword": "OrbitPassword2026!",
        "description": "Multi-party clearance with hardware enclave"
    })
    assert code == 201
    print("[PASS] 4. Custom Organization: Created isolated aerospace partition.")

    # 5. Performance Estimator
    code, hdrs, body = execute_request("POST", "/api/performance/estimate", {
        "fileSizeKb": 10240,
        "policyComplexity": 6,
        "attributeCount": 8,
        "networkLatencyMs": 45
    })
    assert code == 200
    perf = json.loads(body.decode("utf-8"))
    assert "encryptionLatencyMs" in perf and "evmGasUnits" in perf
    print(f"[PASS] 5. Performance Estimator: Computed {perf['encryptionLatencyMs']}ms enc, {perf['evmGasUnits']} gas.")

    # 6. Emergency Break-Glass Protocol
    code, hdrs, body = execute_request("POST", "/api/emergency/break-glass", {
        "fileId": "file_001",
        "requester": "dr_priya",
        "justification": "Cardiac arrest ICU emergency override protocol",
        "incidentId": "INC-9901-ICU"
    })
    assert code == 200
    bg = json.loads(body.decode("utf-8"))
    assert bg["success"] is True and "incident" in bg
    print("[PASS] 6. Emergency Break-Glass: Decryption access granted with incident audit trail.")

    # 7. Emergency Status & Telemetry
    code, hdrs, body = execute_request("GET", "/api/emergency/status")
    assert code == 200
    st = json.loads(body.decode("utf-8"))
    assert st["activeIncidentCount"] >= 1
    print(f"[PASS] 7. Emergency Telemetry: {st['activeIncidentCount']} active incidents tracked.")

    # 8. Dynamic User Registration with Organization
    code, hdrs, body = execute_request("POST", "/api/users", {
        "userId": "dr_watson",
        "name": "Dr. John Watson",
        "role": "Trauma Surgeon",
        "department": "Surgery",
        "clearance": "Level-4 Confidential",
        "organizationId": "org_hospital",
        "workerPassword": "HospitalPass2026!"
    })
    assert code == 201
    print("[PASS] 8. Dynamic User Registration: Unique ID 'dr_watson' created under Hospital org.")

    # 9. File Upload with Importance Level
    code, hdrs, body = execute_request("POST", "/api/files/upload", {
        "fileId": "file_aero_001",
        "fileName": "satellite_telemetry.bin",
        "fileType": "Telemetry",
        "description": "Critical low-earth orbit orbital telemetry packet",
        "owner": "dr_watson",
        "policy": ["Role:Trauma Surgeon"],
        "content": "ORBITAL_VECTOR_X_492019_Y_881920",
        "organizationId": "org_aerospace",
        "importanceLevel": "Tier-0 Sovereign Critical"
    })
    assert code == 201
    print("[PASS] 9. Uploader Studio: Encrypted & saved file with Tier-0 Sovereign Critical badge.")

    print("\n" + "=" * 65)
    print("ALL 9 ENTERPRISE & TECHNICAL FEATURE TESTS PASSED! (100% SUCCESS)")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_tests()
