#!/usr/bin/env python3
"""
server.py
---------
Production-grade multi-threaded HTTP server providing:
1. RESTful JSON API for Blockchain Cloud Storage (BCS) system
2. Static file server for the modern, colorful frontend application
3. Full CORS support for cross-origin frontend clients
4. Zero third-party dependencies — runs on Python 3 standard library
"""

import os
import sys
import json
import time
import mimetypes
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from backend_service import SERVICE

FRONTEND_DIR = os.path.join(CURRENT_DIR, "frontend")


class BCSRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}\n")

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception as e:
            raise ValueError(f"Malformed JSON body: {e}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/api/"):
            try:
                self._handle_api_get(path, query)
            except Exception as e:
                self._send_json(500, {"error": str(e), "path": path})
            return

        # Default fallback to index.html for SPA client-side routing if file doesn't exist
        file_path = os.path.join(FRONTEND_DIR, path.lstrip("/"))
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            index_path = os.path.join(FRONTEND_DIR, "index.html")
            if os.path.exists(index_path):
                self.path = "/index.html"

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            try:
                body = self._read_json_body()
                self._handle_api_post(path, body)
            except ValueError as ve:
                self._send_json(400, {"error": str(ve)})
            except PermissionError as pe:
                self._send_json(403, {"error": str(pe)})
            except Exception as e:
                self._send_json(500, {"error": str(e), "path": path})
            return
        self._send_json(404, {"error": "Not Found"})

    # --- API GET Router ---
    def _handle_api_get(self, path: str, query: dict):
        # 1. Health
        if path == "/api/health":
            self._send_json(200, {
                "status": "healthy",
                "service": "Blockchain Cloud Storage (BCS) API",
                "version": "1.0.0",
                "time": time.time()
            })
            return

        # 2. Overview Metrics
        if path == "/api/overview":
            self._send_json(200, SERVICE.get_overview_metrics())
            return

        # 3. Users List
        if path == "/api/users":
            self._send_json(200, SERVICE.get_users())
            return

        # 4. User Details
        if path.startswith("/api/users/"):
            uid = path.replace("/api/users/", "").strip()
            user = SERVICE.get_user(uid)
            if user:
                self._send_json(200, user)
            else:
                self._send_json(404, {"error": f"User '{uid}' not found"})
            return

        # 5. Files List
        if path == "/api/files":
            self._send_json(200, SERVICE.list_files())
            return

        # 6. File Details
        if path.startswith("/api/files/"):
            # Check for check-access sub-route: /api/files/:id/check-access?user=xxx
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[3] == "check-access":
                fid = parts[2]
                user_param = query.get("user", [""])[0]
                if not user_param:
                    self._send_json(400, {"error": "Missing 'user' query parameter"})
                    return
                self._send_json(200, SERVICE.check_access(fid, user_param))
                return

            if len(parts) == 4 and parts[3] == "authorized-users":
                fid = parts[2]
                try:
                    self._send_json(200, SERVICE.get_file_authorized_users(fid))
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            fid = parts[2]
            f_detail = SERVICE.get_file_details(fid)
            if f_detail:
                self._send_json(200, f_detail)
            else:
                self._send_json(404, {"error": f"File '{fid}' not found"})
            return

        # 7. Audit Trail
        if path == "/api/audit":
            f_event = query.get("event", [None])[0]
            f_file = query.get("file", query.get("fileId", [None]))[0]
            f_user = query.get("user", [None])[0]
            f_org = query.get("org", [None])[0]
            search = query.get("search", [None])[0]
            caller = query.get("caller", [None])[0]
            logs = SERVICE.get_audit_trail(
                filter_event=f_event,
                filter_file=f_file,
                filter_user=f_user,
                filter_org=f_org,
                search=search,
                caller=caller
            )
            self._send_json(200, logs)
            return

        # 7a. Cryptographic Merkle Root
        if path == "/api/audit/merkle-root":
            self._send_json(200, {"merkleRoot": SERVICE.get_audit_merkle_root()})
            return

        # 7b. Merkle Inclusion Proof
        if path == "/api/audit/proof":
            idx = int(query.get("index", ["1"])[0])
            try:
                proof = SERVICE.get_event_merkle_proof(idx)
                self._send_json(200, proof)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 7e. Audit Permissions
        if path == "/api/audit/permissions":
            fid = query.get("fileId", [None])[0]
            oid = query.get("orgId", [None])[0]
            self._send_json(200, SERVICE.get_audit_permissions(fid, oid))
            return

        # 10a. Emergency Whitelist
        if path == "/api/emergency/whitelist":
            fid = query.get("fileId", ["file_001"])[0]
            try:
                self._send_json(200, SERVICE.get_file_emergency_whitelist(fid))
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 7c. W3C DID Document
        if path.startswith("/api/identity/did/"):
            uid = path.split("/")[4]
            try:
                doc = SERVICE.get_user_did_document(uid)
                self._send_json(200, doc)
            except Exception as e:
                self._send_json(404, {"error": str(e)})
            return

        # 7d. W3C Verifiable Credentials
        if path.startswith("/api/identity/vc/"):
            uid = path.split("/")[4]
            try:
                vcs = SERVICE.get_user_verifiable_credentials(uid)
                self._send_json(200, {"userId": uid, "credentials": vcs})
            except Exception as e:
                self._send_json(404, {"error": str(e)})
            return

        # 8. Benchmarks
        if path == "/api/benchmarks":
            self._send_json(200, SERVICE.run_benchmarks())
            return

        # 9. Organizations List
        if path == "/api/organizations":
            self._send_json(200, SERVICE.get_organizations())
            return

        # 9a. Organization Workers Directory
        if path.startswith("/api/organizations/") and path.endswith("/workers"):
            org_id = path.split("/")[3]
            try:
                workers = SERVICE.get_organization_workers(org_id)
                self._send_json(200, workers)
            except Exception as e:
                self._send_json(404, {"error": str(e)})
            return

        # 9b. Organization Authorized Members Roster
        if path.startswith("/api/organizations/") and path.endswith("/members"):
            org_id = path.split("/")[3]
            try:
                members = SERVICE.get_organization_members(org_id)
                self._send_json(200, members)
            except Exception as e:
                self._send_json(404, {"error": str(e)})
            return

        # 10. Emergency Status
        if path == "/api/emergency/status":
            self._send_json(200, SERVICE.get_emergency_status())
            return

        # 11. Performance Estimate (GET support)
        if path == "/api/performance/estimate":
            try:
                sz = float(query.get("size", [100.0])[0])
                attrs = int(query.get("attrs", [3])[0])
                logic = query.get("logic", ["AND"])[0]
                storage = query.get("storage", ["IPFS"])[0]
                self._send_json(200, SERVICE.get_performance_estimate(sz, attrs, logic, storage))
            except Exception as e:
                self._send_json(400, {"error": str(e)})
        # 12. Data Classifications List
        if path == "/api/classifications":
            self._send_json(200, SERVICE.get_classifications())
            return

        # 13. Sample Excel (.xlsx) Template for Whitelisted Names
        if path == "/api/utils/sample-whitelist-excel":
            import base64
            xlsx_bytes = SERVICE.generate_sample_whitelist_xlsx()
            b64_str = base64.b64encode(xlsx_bytes).decode("ascii")
            self._send_json(200, {
                "success": True,
                "filename": "whitelisted_usernames_sample.xlsx",
                "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "contentBase64": b64_str,
                "base64": b64_str
            })
            return

        self._send_json(404, {"error": f"API endpoint '{path}' not found"})

    # --- API POST Router ---
    def _handle_api_post(self, path: str, body: dict):
        # 1. User Creation
        if path == "/api/users":
            uid = body.get("userId", "")
            name = body.get("name", "")
            role = body.get("role", "User")
            dept = body.get("department", "General")
            clearance = body.get("clearance", "Level-1 Basic")
            email = body.get("email", "")
            org_id = body.get("organizationId", "org_general")
            worker_pwd = body.get("workerPassword", "")
            roles = body.get("roles", None)
            if not uid or not name:
                self._send_json(400, {"error": "userId and name are required"})
                return
            created = SERVICE.create_user(
                user_id=uid, name=name, role=role, department=dept,
                clearance=clearance, organization_id=org_id, worker_password=worker_pwd,
                roles=roles
            )
            self._send_json(201, created)
            return

        # 2. Issue Attribute
        if path == "/api/users/issue-attribute":
            uid = body.get("userId", "")
            attr = body.get("attribute", "")
            if not uid or not attr:
                self._send_json(400, {"error": "userId and attribute are required"})
                return
            res = SERVICE.issue_attribute(uid, attr)
            self._send_json(200, res)
            return

        # 3. Revoke Attribute
        if path == "/api/users/revoke-attribute":
            uid = body.get("userId", "")
            attr = body.get("attribute", "")
            if not uid or not attr:
                self._send_json(400, {"error": "userId and attribute are required"})
                return
            res = SERVICE.revoke_attribute(uid, attr)
            self._send_json(200, res)
            return

        # 4. Upload & Register File (Step 1-3)
        if path == "/api/files/upload":
            fid = body.get("fileId", "").strip()
            fname = body.get("fileName", "").strip()
            desc = body.get("description", "").strip()
            ftype = body.get("fileType", "Document").strip()
            owner = body.get("owner", "dr_priya").strip()
            policy = body.get("policy", ["Role:Doctor"])
            content = body.get("content", "")
            is_binary = body.get("isBinary", False)
            mime_type = body.get("mimeType", "text/plain")

            if is_binary and isinstance(content, str):
                import base64
                if "," in content:
                    content = content.split(",", 1)[1]
                try:
                    plaintext = base64.b64decode(content)
                except Exception as e:
                    self._send_json(400, {"error": f"Invalid base64 payload: {e}"})
                    return
            elif isinstance(content, str):
                plaintext = content.encode("utf-8")
            else:
                plaintext = bytes(content)

            if not plaintext:
                self._send_json(400, {"error": "File content cannot be empty"})
                return

            org_id = body.get("organizationId", "org_general").strip()
            importance = body.get("importanceLevel", "Tier-1 High Enterprise").strip()

            emer_raw = body.get("emergencyWhitelist")
            if isinstance(emer_raw, str):
                emer_list = [s.strip() for s in emer_raw.split(",") if s.strip()]
            else:
                emer_list = emer_raw

            log_raw = body.get("logViewers")
            if isinstance(log_raw, str):
                log_list = [s.strip() for s in log_raw.split(",") if s.strip()]
            else:
                log_list = log_raw

            auth_raw = body.get("authorizedUsers")
            if isinstance(auth_raw, str):
                auth_list = [s.strip() for s in auth_raw.split(",") if s.strip()]
            else:
                auth_list = auth_raw

            res = SERVICE.upload_and_register_file(
                file_id=fid,
                file_name=fname,
                description=desc,
                file_type=ftype,
                owner=owner,
                policy=policy,
                plaintext_bytes=plaintext,
                is_binary=is_binary,
                mime_type=mime_type,
                organization_id=org_id,
                importance_level=importance,
                emergency_whitelist=emer_list,
                log_viewers=log_list,
                authorized_users=auth_list
            )
            self._send_json(201, res)
            return

        # 5. Request Access (Step 4-5)
        if path.startswith("/api/files/") and path.endswith("/request-access"):
            fid = path.split("/")[3]
            requester = body.get("requester", "")
            if not requester:
                self._send_json(400, {"error": "requester is required"})
                return
            res = SERVICE.request_access(fid, requester)
            self._send_json(200, res)
            return

        # 6. Decrypt File (Step 6)
        if path.startswith("/api/files/") and path.endswith("/decrypt"):
            fid = path.split("/")[3]
            user_id = body.get("userId", "")
            if not user_id:
                self._send_json(400, {"error": "userId is required"})
                return
            res = SERVICE.decrypt_file(fid, user_id)
            if res.get("success"):
                self._send_json(200, res)
            else:
                self._send_json(403, res)
            return

        # 7. Revoke User Access (Step 8)
        if path.startswith("/api/files/") and path.endswith("/revoke"):
            fid = path.split("/")[3]
            target_user = body.get("userId", "")
            caller = body.get("caller", "")
            if not target_user or not caller:
                self._send_json(400, {"error": "userId and caller are required"})
                return
            res = SERVICE.revoke_user_access(fid, target_user, caller)
            self._send_json(200, res)
            return

        # 8. Emergency Kill Switch (Revoke All)
        if path.startswith("/api/files/") and path.endswith("/revoke-all"):
            fid = path.split("/")[3]
            caller = body.get("caller", "")
            if not caller:
                self._send_json(400, {"error": "caller is required"})
                return
            res = SERVICE.revoke_all_access(fid, caller)
            self._send_json(200, res)
            return

        # 9. Restore File Access
        if path.startswith("/api/files/") and path.endswith("/restore-all"):
            fid = path.split("/")[3]
            caller = body.get("caller", "")
            if not caller:
                self._send_json(400, {"error": "caller is required"})
                return
            res = SERVICE.restore_all_access(fid, caller)
            self._send_json(200, res)
            return

        # 9b. Grant Direct File Access to User
        if (path.startswith("/api/files/") and path.endswith("/grant-user")) or path == "/api/files/permissions/grant":
            fid = path.split("/")[3] if "/grant-user" in path else body.get("fileId", body.get("targetId", ""))
            uid = body.get("userId", body.get("username", ""))
            caller = body.get("caller", "")
            try:
                res = SERVICE.grant_file_access(fid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 9c. Revoke Direct File Access from User
        if (path.startswith("/api/files/") and path.endswith("/revoke-user")) or path == "/api/files/permissions/revoke":
            fid = path.split("/")[3] if "/revoke-user" in path else body.get("fileId", body.get("targetId", ""))
            uid = body.get("userId", body.get("username", ""))
            caller = body.get("caller", "")
            try:
                res = SERVICE.revoke_file_access(fid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 10. Run Fresh Benchmarks
        if path == "/api/benchmarks/run":
            res = SERVICE.run_benchmarks()
            self._send_json(200, res)
            return

        # 11. Reset Demo Data
        if path == "/api/system/reset-demo":
            SERVICE.seed_initial_data()
            self._send_json(200, {"status": "reset_successful", "message": "Demo data reloaded."})
            return

        # 12. Verify Merkle Proof
        if path == "/api/audit/verify-proof":
            leaf = body.get("leafHashHex", "")
            proof = body.get("proofPath", [])
            root = body.get("expectedRootHex", "")
            verified = SERVICE.verify_event_merkle_proof(leaf, proof, root)
            self._send_json(200, {"verified": verified, "rootHex": root})
            return

        # 13. Generate Zero-Knowledge Attribute Proof
        if path == "/api/zk/generate-proof":
            uid = body.get("userId", "")
            attr = body.get("attribute", "")
            try:
                zk = SERVICE.generate_zk_attribute_proof(uid, attr)
                self._send_json(200, zk)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 14. Request Access with Zero-Knowledge Proof
        if path == "/api/zk/request-access":
            fid = body.get("fileId", "")
            uid = body.get("userId", "")
            proof = body.get("zkProof", {})
            try:
                res = SERVICE.request_access_zk(fid, uid, proof)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 15. Evaluate Boolean Policy Tree
        if path == "/api/policy/evaluate":
            expr = body.get("expression", "")
            attrs = body.get("attributes", [])
            try:
                res = SERVICE.evaluate_policy_expression(expr, attrs)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 16. AWS S3 Presigned URL
        if path == "/api/storage/s3-presign":
            fid = body.get("fileId", "")
            action = body.get("action", "PUT")
            res = SERVICE.generate_s3_presigned_url(fid, action)
            self._send_json(200, res)
            return

        # 17. Create Organization
        if path == "/api/organizations":
            oid = body.get("orgId", "")
            name = body.get("name", "")
            sector = body.get("sector", "General Enterprise")
            desc = body.get("description", "")
            roles = body.get("allowedRoles", ["Staff", "Admin"])
            pwd = body.get("workerPassword", "")
            req_pwd = body.get("requirePassword", True)
            min_clear = body.get("minClearance", "Level-1 Public")
            is_priv = body.get("isPrivate", True)
            creator = body.get("creator", "")
            members = body.get("authorizedMembers", [])
            try:
                org = SERVICE.create_organization(
                    org_id=oid, name=name, sector=sector, description=desc,
                    allowed_roles=roles, worker_password=pwd, require_password=req_pwd,
                    min_clearance=min_clear, is_private=is_priv,
                    creator=creator, authorized_members=members
                )
                self._send_json(201, org)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 17b. Add Member to Organization Roster
        if path.startswith("/api/organizations/") and path.endswith("/members"):
            oid = path.split("/")[3]
            uid = body.get("userId", "")
            role = body.get("role", "")
            clearance = body.get("clearance", "")
            caller = body.get("caller", "")
            if not uid:
                self._send_json(400, {"error": "userId is required"})
                return
            try:
                res = SERVICE.add_organization_member(oid, uid, role, caller, clearance=clearance)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 17c. Remove Member from Organization Roster
        if path.startswith("/api/organizations/") and path.endswith("/remove-member"):
            oid = path.split("/")[3]
            uid = body.get("userId", "")
            caller = body.get("caller", "")
            if not uid:
                self._send_json(400, {"error": "userId is required"})
                return
            try:
                res = SERVICE.remove_organization_member(oid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 18. Verify Organization Worker Credentials
        if path == "/api/organizations/verify-worker":
            oid = body.get("orgId", "")
            uid = body.get("userId", "")
            pwd = body.get("password", "")
            try:
                res = SERVICE.verify_worker_credentials(oid, uid, pwd)
                status = 200 if res.get("verified") else 401
                self._send_json(status, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 19. Emergency Break-Glass Request
        if path == "/api/emergency/break-glass":
            fid = body.get("fileId", "")
            req = body.get("requester", "")
            inc = body.get("incidentId", "")
            just = body.get("justification", "")
            ttl = int(body.get("ttlSeconds", 900))
            witness = body.get("dualWitness", "")
            try:
                res = SERVICE.emergency_break_glass(
                    file_id=fid, requester=req, incident_id=inc,
                    justification=just, ttl_seconds=ttl, dual_witness=witness
                )
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 20. Emergency Lockdown
        if path == "/api/emergency/lockdown":
            ttype = body.get("targetType", "file")
            tid = body.get("targetId", "")
            caller = body.get("caller", "")
            reason = body.get("reason", "Emergency Security Quarantine")
            try:
                res = SERVICE.emergency_lockdown(ttype, tid, caller, reason)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 21. Restore Emergency Lockdown
        if path == "/api/emergency/restore":
            ttype = body.get("targetType", "file")
            tid = body.get("targetId", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.restore_lockdown(ttype, tid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 22. Technical Performance Estimate (POST)
        if path == "/api/performance/estimate":
            sz = float(body.get("fileSizeKb", 100.0))
            attrs = int(body.get("attributeCount", 3))
            logic = body.get("logicType", "AND")
            storage = body.get("storageBackend", "IPFS")
            try:
                res = SERVICE.get_performance_estimate(sz, attrs, logic, storage)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 23. Log File Reading Session & Exact Dwell Duration
        if path == "/api/audit/log-session":
            fid = body.get("fileId", "")
            uid = body.get("userId", "")
            dwell = float(body.get("dwellTimeSeconds", 0.0))
            action = body.get("action", "File Reading & Inspection")
            details = body.get("details", "")
            try:
                res = SERVICE.log_file_session(fid, uid, dwell, action, details)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return
        # 24. Multi-Role: Add Role to User Profile
        if path.startswith("/api/users/") and path.endswith("/roles"):
            uid = path.split("/")[3]
            role = body.get("role", "")
            dept = body.get("department", "")
            if not uid or not role:
                self._send_json(400, {"error": "userId and role are required"})
                return
            try:
                res = SERVICE.add_role_to_user(uid, role, dept)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 25. Multi-Role: Switch Active Role
        if path.startswith("/api/users/") and path.endswith("/switch-role"):
            uid = path.split("/")[3]
            role = body.get("role", "")
            if not uid or not role:
                self._send_json(400, {"error": "userId and role are required"})
                return
            try:
                res = SERVICE.switch_user_role(uid, role)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 26. Data Classifications: Create Custom Classification
        if path == "/api/classifications":
            lbl = body.get("label", "")
            desc = body.get("description", "")
            color = body.get("color", "#3b82f6")
            b_class = body.get("badgeClass", "badge-indigo")
            score = body.get("sensitivityScore", 70)
            if not lbl:
                self._send_json(400, {"error": "Classification label is required"})
                return
            try:
                res = SERVICE.add_classification(
                    label=lbl, description=desc, color=color,
                    badge_class=b_class, sensitivity_score=score
                )
                self._send_json(201, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 27. Front-Door User Authentication (Login)
        if path == "/api/auth/login":
            uid = body.get("userId", "")
            pwd = body.get("password", "")
            res = SERVICE.authenticate_user(uid, pwd)
            status = 200 if res.get("success") else 401
            self._send_json(status, res)
            return

        # 28. Front-Door Account Registration (Step 1 & 2)
        if path == "/api/auth/register":
            uid = body.get("userId", "").strip()
            pwd = body.get("password", "").strip()
            name = body.get("name", "").strip()
            org_id = body.get("organizationId", "org_general").strip()
            try:
                res = SERVICE.register_account(uid, pwd, name, org_id)
                self._send_json(201, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 28b. Front-Door Account Verification for Password Reset
        if path == "/api/auth/verify-reset-user":
            uid = body.get("userId") or body.get("username", "")
            try:
                res = SERVICE.verify_account_for_reset(uid)
                self._send_json(200, res)
            except LookupError as e:
                self._send_json(404, {"verified": False, "error": str(e)})
            except Exception as e:
                self._send_json(400, {"verified": False, "error": str(e)})
            return

        # 28c. Front-Door Forgot Password / Reset Password
        if path in ("/api/auth/reset-password", "/api/auth/forgot-password"):
            uid = body.get("userId") or body.get("username", "")
            new_pwd = body.get("newPassword") or body.get("password", "")
            confirm_pwd = body.get("confirmPassword")
            try:
                res = SERVICE.reset_account_password(uid, new_pwd, confirm_pwd)
                self._send_json(200, res)
            except LookupError as e:
                self._send_json(404, {"reset": False, "error": str(e)})
            except Exception as e:
                self._send_json(400, {"reset": False, "error": str(e)})
            return

        # 29. Organization Creator: Update Member Role & Confidentiality Clearance
        if path.startswith("/api/organizations/") and path.endswith("/update-member"):
            oid = path.split("/")[3]
            uid = body.get("userId", "")
            role = body.get("role", "")
            clearance = body.get("clearance", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.update_member_clearance_and_role(oid, uid, role, clearance, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 30. Audit Log Permissions: Grant Access
        if path == "/api/audit/permissions/grant":
            ttype = body.get("targetType", "file")
            tid = body.get("targetId") or body.get("fileId", "")
            uid = body.get("userId") or body.get("username", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.grant_log_viewer_access(ttype, tid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 31. Audit Log Permissions: Revoke Access
        if path == "/api/audit/permissions/revoke":
            ttype = body.get("targetType", "file")
            tid = body.get("targetId") or body.get("fileId", "")
            uid = body.get("userId") or body.get("username", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.revoke_log_viewer_access(ttype, tid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 32. Emergency Whitelist: Add Responder
        if path == "/api/emergency/whitelist/add":
            fid = body.get("fileId") or body.get("targetId", "")
            uid = body.get("userId") or body.get("username", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.add_file_emergency_whitelist(fid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 33. Emergency Whitelist: Remove Responder
        if path == "/api/emergency/whitelist/remove":
            fid = body.get("fileId") or body.get("targetId", "")
            uid = body.get("userId") or body.get("username", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.remove_file_emergency_whitelist(fid, uid, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 34. Emergency Incident: Resolve / Terminate Incident
        if path == "/api/emergency/resolve":
            inc_id = body.get("incidentId", "")
            caller = body.get("caller", "")
            try:
                res = SERVICE.resolve_emergency_incident(inc_id, caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 35. Emergency Incident: Resolve All Active Emergencies
        if path == "/api/emergency/resolve-all":
            caller = body.get("caller", "")
            try:
                res = SERVICE.resolve_all_emergencies(caller)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 36. Excel / CSV Bulk Usernames Parser
        if path == "/api/utils/parse-excel-usernames":
            import base64
            file_b64 = body.get("contentBase64") or body.get("fileBase64") or body.get("content", "")
            filename = body.get("filename", "names.xlsx")
            org_id = body.get("defaultOrg") or body.get("organizationId", "General Commons")
            if isinstance(file_b64, str) and "," in file_b64:
                file_b64 = file_b64.split(",", 1)[1]
            try:
                raw_bytes = base64.b64decode(file_b64) if file_b64 else b""
                res = SERVICE.parse_excel_usernames(raw_bytes, filename=filename, default_org=org_id)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"success": False, "error": str(e)})
            return

        self._send_json(404, {"error": f"POST endpoint '{path}' not found"})


def run_server(port=8000, host="0.0.0.0"):
    os.makedirs(FRONTEND_DIR, exist_ok=True)
    ThreadingHTTPServer.allow_reuse_address = True

    server = None
    target_port = port
    max_attempts = 10

    for attempt in range(max_attempts):
        try:
            server = ThreadingHTTPServer((host, target_port), BCSRequestHandler)
            break
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[Notice] Port {target_port} is currently in use. Trying port {target_port + 1}...")
                target_port += 1
            else:
                raise e

    if server is None:
        raise OSError(f"Could not bind to any port from {port} to {port + max_attempts - 1}")

    print(f"\n========================================================")
    print(f"  BLOCKCHAIN CLOUD STORAGE (BCS) FULL-STACK SERVER")
    print(f"========================================================")
    print(f"  Web Application : http://localhost:{target_port}/")
    print(f"  API Backend URL : http://localhost:{target_port}/api/")
    print(f"  Host & Port     : {host}:{target_port}")
    print(f"  Status          : Active & Ready")
    print(f"========================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    import argparse
    default_port = int(os.environ.get("PORT", 8000))
    parser = argparse.ArgumentParser(description="BCS Full-Stack Server")
    parser.add_argument("positional_port", nargs="?", type=int, default=None, help="Optional port number (e.g. 8080)")
    parser.add_argument("--port", type=int, default=None, help="Port to listen on (default: $PORT or 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    args = parser.parse_args()
    
    selected_port = args.port or args.positional_port or default_port
    run_server(port=selected_port, host=args.host)
