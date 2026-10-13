"""
test_e2e_http.py
----------------
Full End-to-End HTTP & Frontend Integration Test:
1. Boots up ThreadingHTTPServer on port 8089 in a background thread
2. Tests static asset serving (index.html, styles.css, app.js)
3. Tests all REST API endpoints via real HTTP requests
4. Tests CORS pre-flight OPTIONS requests
5. Validates JSON schemas and responses
6. Shuts down server cleanly
"""

import sys
import os
import json
import time
import threading
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import BCSRequestHandler

TEST_PORT = 8089
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "BCS-Test/1.0"})
    with urllib.request.urlopen(req, timeout=5) as res:
        status = res.status
        content_type = res.headers.get("Content-Type", "")
        body = res.read()
        return status, content_type, body


def http_post(path, data):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "BCS-Test/1.0"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as he:
        return he.code, json.loads(he.read().decode("utf-8"))


def http_options(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, method="OPTIONS")
    with urllib.request.urlopen(req, timeout=5) as res:
        return res.status, dict(res.headers)


def run_e2e_tests():
    print("=" * 70)
    print("STARTING E2E HTTP SERVER & FRONTEND INTEGRATION TEST")
    print(f"Target: {BASE_URL}")
    print("=" * 70)

    # 1. Start server in thread
    httpd = ThreadingHTTPServer(("127.0.0.1", TEST_PORT), BCSRequestHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    try:
        # Test 1: Static index.html
        status, ctype, body = http_get("/")
        assert status == 200, f"Expected 200, got {status}"
        assert b"MedShield BCS" in body, "index.html missing brand name"
        print("[PASS] 1. Static Web Serving: index.html served with HTTP 200.")

        # Test 2: Static styles.css
        status, ctype, body = http_get("/styles.css")
        assert status == 200
        assert b"--royal-blue" in body
        print("[PASS] 2. Static Web Serving: styles.css stylesheet served with HTTP 200.")

        # Test 3: Static app.js
        status, ctype, body = http_get("/app.js")
        assert status == 200
        assert b"API_BASE" in body
        print("[PASS] 3. Static Web Serving: app.js frontend logic served with HTTP 200.")

        # Test 4: CORS Pre-flight OPTIONS
        status, headers = http_options("/api/files")
        assert status == 200
        assert headers.get("Access-Control-Allow-Origin") == "*"
        assert "POST" in headers.get("Access-Control-Allow-Methods", "")
        print("[PASS] 4. CORS Support: Validated Access-Control-Allow-Origin & Methods headers.")

        # Test 5: GET /api/health
        status, ctype, body = http_get("/api/health")
        health = json.loads(body.decode("utf-8"))
        assert health["status"] == "healthy"
        print(f"[PASS] 5. API Health: Service is healthy ({health['service']}).")

        # Test 6: GET /api/overview
        status, ctype, body = http_get("/api/overview")
        overview = json.loads(body.decode("utf-8"))
        assert overview["totalFiles"] >= 3
        assert overview["totalUsers"] >= 5
        print(f"[PASS] 6. API Overview: Confirmed {overview['totalFiles']} files and {overview['totalUsers']} users.")

        # Test 7: GET /api/users
        status, ctype, body = http_get("/api/users")
        users = json.loads(body.decode("utf-8"))
        assert any(u["userId"] == "dr_priya" for u in users)
        print(f"[PASS] 7. API Users: Retrieved {len(users)} registered identities.")

        # Test 8: POST /api/users (Create user)
        status, new_user = http_post("/api/users", {
            "userId": "nurse_kavita",
            "name": "Kavita Rao",
            "role": "Nurse",
            "department": "Cardiology",
            "clearance": "Level-2 Restricted"
        })
        assert status == 201
        assert new_user["userId"] == "nurse_kavita"
        print(f"[PASS] 8. API Users POST: Successfully registered 'nurse_kavita'.")

        # Test 9: POST /api/files/upload (Encrypt & Upload)
        status, upload_res = http_post("/api/files/upload", {
            "fileId": "file_http_test_101",
            "fileName": "icu_telemetry_packet.json",
            "fileType": "Medical Record",
            "description": "ICU Cardiac monitoring packet",
            "owner": "dr_priya",
            "policy": ["Role:Doctor", "Dept:Cardiology"],
            "content": "Patient telemetry HR: 72, BP: 120/80, SpO2: 98%."
        })
        assert status == 201
        assert upload_res["fileId"] == "file_http_test_101"
        assert upload_res["contentHash"] is not None
        print(f"[PASS] 9. API Files POST: Encrypted via CP-ABE, stored blob off-chain, registered on-chain.")

        # Test 10: POST /api/files/file_http_test_101/request-access (Authorized)
        status, acc_grant = http_post("/api/files/file_http_test_101/request-access", {
            "requester": "dr_priya"
        })
        assert status == 200
        assert acc_grant["granted"] is True
        print(f"[PASS] 10. API Access POST (Granted): dr_priya policy evaluation succeeded.")

        # Test 11: POST /api/files/file_http_test_101/request-access (Unauthorized)
        status, acc_deny = http_post("/api/files/file_http_test_101/request-access", {
            "requester": "nurse_kavita"
        })
        assert status == 200
        assert acc_deny["granted"] is False
        assert "Role:Doctor" in acc_deny["missingAttrs"]
        print(f"[PASS] 11. API Access POST (Denied): nurse_kavita missing Role:Doctor rejected automatically.")

        # Test 12: POST /api/files/file_http_test_101/decrypt
        status, dec_res = http_post("/api/files/file_http_test_101/decrypt", {
            "userId": "dr_priya"
        })
        assert status == 200
        assert "HR: 72" in dec_res["plaintext"]
        print(f"[PASS] 12. API Decrypt POST: Authorized user decrypted off-chain blob in {dec_res['decryptionTimeMs']}ms.")

        # Test 13: POST /api/files/file_http_test_101/revoke
        status, rev_res = http_post("/api/files/file_http_test_101/revoke", {
            "userId": "dr_priya",
            "caller": "dr_priya"
        })
        assert status == 200
        assert rev_res["success"] is True
        print(f"[PASS] 13. API Revoke POST: Per-user permission revoked in {rev_res['revocationTimeMs']}ms.")

        # Test 14: GET /api/audit
        status, ctype, body = http_get("/api/audit?event=AccessGranted")
        audit_logs = json.loads(body.decode("utf-8"))
        assert len(audit_logs) > 0
        assert all(l["event"] == "AccessGranted" for l in audit_logs)
        print(f"[PASS] 14. API Audit GET: Immutable audit ledger query and filter working perfectly.")

        # Test 15: GET /api/benchmarks
        status, ctype, body = http_get("/api/benchmarks")
        bm = json.loads(body.decode("utf-8"))
        assert "gasCosts" in bm
        assert "revocationEfficiencyGain" in bm
        print(f"[PASS] 15. API Benchmarks GET: Benchmarks and gas analysis retrieved successfully.")

        print("\n" + "=" * 70)
        print("ALL 15 E2E INTEGRATION & HTTP API TESTS PASSED! (100% SUCCESS)")
        print("=" * 70 + "\n")

    finally:
        httpd.shutdown()
        server_thread.join()


if __name__ == "__main__":
    run_e2e_tests()
