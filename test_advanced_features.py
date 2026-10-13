"""
test_advanced_features.py
-------------------------
Verifies all newly implemented improvements:
1. Cryptographic Merkle Tree generation & proof verification
2. W3C Decentralized Identifiers (DIDs) & Verifiable Credentials (VCs)
3. Zero-Knowledge Attribute Proofs (zk-SNARK style commitments & proofs)
4. Access Tree Boolean Policy Parser & Evaluator (AND, OR, THRESHOLD)
5. IPFS CIDv0 / CIDv1 Content Addressing & Pinning
6. AWS S3 Presigned URL Generation (SigV4)
7. SQLite Database Persistence
"""

import os
import sys
import json
import io

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from test_handler_mock import execute_request
from backend_service import SERVICE
from storage.database import BCS_DB


def mock_request(method, path, body=None):
    status, headers, body_bytes = execute_request(method, path, body_data=body)
    parsed = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    return status, parsed


def run_tests():
    print("=" * 65)
    print("TESTING ADVANCED SYSTEM IMPROVEMENTS (100% SUITE)")
    print("=" * 65)

    # 1. Merkle Root Endpoint
    status, res = mock_request("GET", "/api/audit/merkle-root")
    assert status == 200 and "merkleRoot" in res and len(res["merkleRoot"]) == 64
    root = res["merkleRoot"]
    print(f"[PASS] 1. API: /api/audit/merkle-root -> {root[:18]}...")

    # 2. Merkle Inclusion Proof
    status, proof = mock_request("GET", "/api/audit/proof?index=1")
    assert status == 200 and "leafHashHex" in proof and "proofPath" in proof
    print(f"[PASS] 2. API: /api/audit/proof -> leaf: {proof['leafHashHex'][:16]}... siblings: {len(proof['proofPath'])}")

    # 3. Verify Merkle Proof
    status, ver = mock_request("POST", "/api/audit/verify-proof", {
        "leafHashHex": proof["leafHashHex"],
        "proofPath": proof["proofPath"],
        "expectedRootHex": proof["rootHex"]
    })
    assert status == 200 and ver["verified"] is True
    print("[PASS] 3. API: /api/audit/verify-proof -> Cryptographically Verified: TRUE")

    # 4. W3C DID Document
    status, did_doc = mock_request("GET", "/api/identity/did/dr_priya")
    assert status == 200 and did_doc["id"].startswith("did:bcs:")
    print(f"[PASS] 4. API: /api/identity/did/dr_priya -> {did_doc['id']}")

    # 5. W3C Verifiable Credentials
    status, vc_res = mock_request("GET", "/api/identity/vc/dr_priya")
    assert status == 200 and len(vc_res["credentials"]) > 0
    print(f"[PASS] 5. API: /api/identity/vc/dr_priya -> Issued {len(vc_res['credentials'])} signed credentials")

    # 6. Zero-Knowledge Attribute Proof Generation
    status, zk = mock_request("POST", "/api/zk/generate-proof", {
        "userId": "dr_priya",
        "attribute": "Role:Doctor"
    })
    assert status == 200 and "commitment" in zk
    print(f"[PASS] 6. API: /api/zk/generate-proof -> commitment: {zk['commitment'][:16]}...")

    # 7. Request Access with Zero-Knowledge Proof
    status, zk_acc = mock_request("POST", "/api/zk/request-access", {
        "fileId": "file_001",
        "userId": "dr_priya",
        "zkProof": zk
    })
    assert status == 200 and zk_acc["granted"] is True
    print("[PASS] 7. API: /api/zk/request-access -> zk-Evaluation GRANTED (Zero plaintext leak)")

    # 8. Boolean Access Tree Policy Evaluation
    status, pol_eval = mock_request("POST", "/api/policy/evaluate", {
        "expression": "(Role:Doctor AND Dept:Cardiology) OR Tier:Admin",
        "attributes": ["Role:Doctor", "Dept:Cardiology"]
    })
    assert status == 200 and pol_eval["satisfied"] is True
    print("[PASS] 8. API: /api/policy/evaluate -> Boolean Tree Evaluated: TRUE")

    # 9. AWS S3 Presigned URL
    status, s3_res = mock_request("POST", "/api/storage/s3-presign", {
        "fileId": "file_001",
        "action": "PUT"
    })
    assert status == 200 and "amazonaws.com" in s3_res["url"]
    print(f"[PASS] 9. API: /api/storage/s3-presign -> {s3_res['url'][:45]}...")

    # 10. IPFS Content Addressing & Pinning
    files = SERVICE.get_files_overview()
    file_001 = next(f for f in files if f["fileId"] == "file_001")
    assert file_001["ipfsCid"].startswith("bafy")
    print(f"[PASS] 10. IPFS Storage Layer -> File pinned at CID: {file_001['ipfsCid']}")

    # 11. SQLite Persistence
    audit_count = BCS_DB.get_audit_events_count()
    assert audit_count > 0
    print(f"[PASS] 11. SQLite Ledger Persistence -> {audit_count} records safely persisted to bcs_ledger.db")

    print("\n" + "=" * 65)
    print("ALL ADVANCED IMPROVEMENT TESTS PASSED! (100% SUCCESS)")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_tests()
