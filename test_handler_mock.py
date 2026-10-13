"""
test_handler_mock.py
--------------------
Tests BCSRequestHandler directly using in-memory Byte streams (no network sockets needed).
Verifies:
1. Static files: GET / (index.html), GET /styles.css, GET /app.js
2. CORS OPTIONS pre-flight
3. API GET /api/health, /api/overview, /api/users, /api/files, /api/audit, /api/benchmarks
4. API POST /api/users, /api/files/upload, /api/files/:id/request-access, /api/files/:id/decrypt, /api/files/:id/revoke
"""

import os
import sys
import json
import io

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from server import BCSRequestHandler, FRONTEND_DIR


class MockSocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode or 'b' in mode:
            return self.rfile
        return self.wfile


class MockServer:
    def __init__(self):
        pass


def execute_request(method, path, body_data=None, headers=None):
    hdrs = headers or {}
    body_bytes = b""
    if body_data is not None:
        body_bytes = json.dumps(body_data).encode("utf-8")
        hdrs["Content-Length"] = str(len(body_bytes))
        hdrs["Content-Type"] = "application/json"

    raw_req = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
    for k, v in hdrs.items():
        raw_req += f"{k}: {v}\r\n"
    raw_req += "\r\n"

    req_stream = io.BytesIO(raw_req.encode("utf-8") + body_bytes)
    out_stream = io.BytesIO()

    # Subclass handler to capture I/O
    class TestableHandler(BCSRequestHandler):
        def __init__(self):
            self.directory = FRONTEND_DIR
            self.client_address = ("127.0.0.1", 54321)
            self.server = None
            self.rfile = req_stream
            self.wfile = out_stream
            self.headers = None
            self.path = path
            self.command = method
            self.close_connection = True
            self.handle_one_request()

    handler = TestableHandler()
    out_bytes = out_stream.getvalue()

    # Parse response
    parts = out_bytes.split(b"\r\n\r\n", 1)
    header_block = parts[0].decode("utf-8", errors="replace")
    body_part = parts[1] if len(parts) > 1 else b""

    lines = header_block.split("\r\n")
    status_line = lines[0] if lines else ""
    status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            hk, hv = line.split(":", 1)
            resp_headers[hk.strip()] = hv.strip()

    return status_code, resp_headers, body_part


def run_tests():
    print("=" * 65)
    print("TESTING BCS HTTP SERVER HANDLER (IN-MEMORY SOCKET-FREE)")
    print("=" * 65)

    # 1. Static index.html
    code, hdrs, body = execute_request("GET", "/")
    assert code == 200, f"Expected 200, got {code}"
    assert (b"OmniVault BCS" in body or b"MedShield BCS" in body)
    print("[PASS] 1. Static asset: index.html served with HTTP 200.")

    # 2. Static styles.css
    code, hdrs, body = execute_request("GET", "/styles.css")
    assert code == 200
    assert b"--royal-blue" in body
    print("[PASS] 2. Static asset: styles.css served with HTTP 200.")

    # 3. Static app.js
    code, hdrs, body = execute_request("GET", "/app.js")
    assert code == 200
    assert b"API_BASE" in body
    print("[PASS] 3. Static asset: app.js served with HTTP 200.")

    # 4. CORS OPTIONS
    code, hdrs, body = execute_request("OPTIONS", "/api/files")
    assert code == 200
    assert hdrs.get("Access-Control-Allow-Origin") == "*"
    print("[PASS] 4. CORS: Preflight OPTIONS sent Access-Control-Allow-Origin: *.")

    # 5. GET /api/health
    code, hdrs, body = execute_request("GET", "/api/health")
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and data["status"] == "healthy"
    print("[PASS] 5. API: /api/health returned healthy status.")

    # 6. GET /api/overview
    code, hdrs, body = execute_request("GET", "/api/overview")
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and data["totalFiles"] >= 3
    print(f"[PASS] 6. API: /api/overview returned {data['totalFiles']} files.")

    # 7. GET /api/users
    code, hdrs, body = execute_request("GET", "/api/users")
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and len(data) >= 5
    print(f"[PASS] 7. API: /api/users returned {len(data)} users.")

    # 8. POST /api/users
    code, hdrs, body = execute_request("POST", "/api/users", {
        "userId": "dr_house",
        "name": "Dr. Gregory House",
        "role": "Chief of Diagnostics",
        "department": "Nephrology",
        "clearance": "Level-5 TopSecret"
    })
    data = json.loads(body.decode("utf-8"))
    assert code == 201 and data["userId"] == "dr_house"
    print("[PASS] 8. API: /api/users registered new identity successfully.")

    # 9. POST /api/files/upload
    code, hdrs, body = execute_request("POST", "/api/files/upload", {
        "fileId": "file_lab_009",
        "fileName": "lumbar_puncture_cytology.pdf",
        "fileType": "Medical Laboratory Report",
        "description": "Cerebrospinal fluid protein and cytology report",
        "owner": "dr_priya",
        "policy": ["Role:Doctor", "Dept:Cardiology"],
        "content": "Normal CSF pressure, protein 35mg/dL, zero oligoclonal bands."
    })
    data = json.loads(body.decode("utf-8"))
    assert code == 201 and data["fileId"] == "file_lab_009"
    print("[PASS] 9. API: /api/files/upload encrypted and registered file.")

    # 10. POST /api/files/file_lab_009/request-access (dr_priya has attributes -> GRANTED)
    code, hdrs, body = execute_request("POST", "/api/files/file_lab_009/request-access", {
        "requester": "dr_priya"
    })
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and data["granted"] is True
    print("[PASS] 10. API: /api/files/:id/request-access evaluated policy -> GRANTED.")

    # 11. POST /api/files/file_lab_009/decrypt
    code, hdrs, body = execute_request("POST", "/api/files/file_lab_009/decrypt", {
        "userId": "dr_priya"
    })
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and data["success"] is True and "Normal CSF" in data["plaintext"]
    print("[PASS] 11. API: /api/files/:id/decrypt recovered plaintext with verified AES-256-GCM tag.")

    # 12. POST /api/files/file_lab_009/revoke
    code, hdrs, body = execute_request("POST", "/api/files/file_lab_009/revoke", {
        "userId": "dr_priya",
        "caller": "dr_priya"
    })
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and data["success"] is True
    print("[PASS] 12. API: /api/files/:id/revoke executed on-chain revocation.")

    # 13. GET /api/audit
    code, hdrs, body = execute_request("GET", "/api/audit?event=AccessRevoked")
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and len(data) > 0
    print(f"[PASS] 13. API: /api/audit returned {len(data)} filtered AccessRevoked events.")

    # 14. GET /api/benchmarks
    code, hdrs, body = execute_request("GET", "/api/benchmarks")
    data = json.loads(body.decode("utf-8"))
    assert code == 200 and "revocationEfficiencyGain" in data
    print(f"[PASS] 14. API: /api/benchmarks measured {data['revocationEfficiencyGain']} speedup.")

    print("\n" + "=" * 65)
    print("ALL 14 HTTP REQUEST HANDLER TESTS PASSED! (100% SUCCESS)")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_tests()
