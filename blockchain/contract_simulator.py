"""
blockchain/contract_simulator.py
----------------------------------
A line-for-line Python mirror of contracts/AccessControl.sol's state
machine and events, extended with:
1. Cryptographic SHA-256 Merkle Tree over all emitted on-chain events
2. Zero-Knowledge Attribute Proof (zk-SNARK style attribute verification)
3. Cryptographic Transaction Hashes (txHash) for every audit log entry
4. SQLite persistence integration for tamper-evident ledger storage
"""

import os
import sys
import time
import json
import hashlib
from typing import List, Dict, Any, Optional

# Ensure imports work
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from blockchain.zk_merkle_contract import AUDIT_MERKLE_TREE, MerkleTree, ZkAttributeProof
from storage.database import BCS_DB


class AccessControlSimulator:
    def __init__(self, attribute_authority="AUTHORITY"):
        self.attribute_authority = attribute_authority
        self.files = {}              # fileId -> dict(owner, contentHash, requiredAttrs, revokedAll)
        self.access = {}             # (fileId, user) -> dict(granted, grantedAt, revokedAt)
        self.user_attributes = {}    # user -> set(attributes)
        self.audit_log = []          # append-only list of events -- the on-chain audit trail
        self.merkle_tree = AUDIT_MERKLE_TREE

    # -- events / audit trail -----------------------------------------
    def _emit(self, event: str, **fields):
        timestamp = time.time()
        raw_payload = f"{event}:{timestamp}:{sorted(fields.items())}"
        tx_hash = "0x" + hashlib.sha256(raw_payload.encode()).hexdigest()
        
        entry = {
            "event": event,
            "timestamp": timestamp,
            "txHash": tx_hash,
            **fields
        }
        self.audit_log.append(entry)

        # Update cryptographic Merkle Tree
        leaf_bytes = json.dumps(entry, sort_keys=True).encode()
        self.merkle_tree.add_leaf(leaf_bytes)
        self.merkle_tree.rebuild()

        # Update SQLite Persistent Database
        try:
            BCS_DB.log_audit_event(entry, tx_hash)
        except Exception:
            pass

        return entry

    def get_merkle_root(self) -> str:
        return self.merkle_tree.get_root_hex()

    def get_merkle_proof(self, event_index: int) -> Dict[str, Any]:
        return self.merkle_tree.generate_proof(event_index)

    def verify_merkle_proof(self, leaf_hash_hex: str, proof_path: List[Dict[str, str]], expected_root_hex: str) -> bool:
        return MerkleTree.verify_proof(leaf_hash_hex, proof_path, expected_root_hex)

    # -- attribute authority (User & Identity Module) -------------------
    def issue_attribute(self, user: str, attribute: str):
        self.user_attributes.setdefault(user, set()).add(attribute)
        self._emit("AttributeIssued", user=user, attribute=attribute)

    def revoke_attribute(self, user: str, attribute: str):
        self.user_attributes.get(user, set()).discard(attribute)
        self._emit("AttributeRevoked", user=user, attribute=attribute)

    def has_attribute(self, user: str, attribute: str) -> bool:
        return attribute in self.user_attributes.get(user, set())

    # -- Step 3: upload / register file ---------------------------------
    def upload_file(self, file_id: str, owner: str, content_hash: str, required_attrs: list[str], ipfs_cid: str = ""):
        if file_id in self.files:
            raise ValueError("fileId already used")
        self.files[file_id] = {
            "owner": owner,
            "contentHash": content_hash,
            "ipfsCid": ipfs_cid,
            "requiredAttrs": list(required_attrs),
            "revokedAll": False,
            "authorizedUsers": [owner],
            "emergencyWhitelistedUsers": [owner],
        }
        self.access[(file_id, owner)] = {
            "granted": True, "grantedAt": time.time(), "revokedAt": None,
        }
        self._emit("FileUploaded", fileId=file_id, owner=owner, contentHash=content_hash, ipfsCid=ipfs_cid)

    # -- Steps 4-5: request access / automatic policy evaluation --------
    def request_access(self, file_id: str, requester: str) -> bool:
        if file_id not in self.files:
            raise ValueError("file not found")
        self._emit("AccessRequested", fileId=file_id, requester=requester)

        f = self.files[file_id]
        if f["revokedAll"]:
            self._emit("AccessDenied", fileId=file_id, requester=requester,
                        reason="file access disabled by owner")
            return False

        is_owner = (requester == f.get("owner"))
        is_authorized = (requester in f.get("authorizedUsers", []))
        is_emergency = (requester in f.get("emergencyWhitelistedUsers", []))

        if not (is_owner or is_authorized or is_emergency):
            for attr in f["requiredAttrs"]:
                if not self.has_attribute(requester, attr):
                    self._emit("AccessDenied", fileId=file_id, requester=requester,
                                reason=f"missing attribute: {attr}")
                    return False

        self.access[(file_id, requester)] = {
            "granted": True, "grantedAt": time.time(), "revokedAt": None,
        }
        self._emit("AccessGranted", fileId=file_id, requester=requester)
        return True

    # -- Zero-Knowledge Proof based access evaluation --------------------
    def request_access_zk(self, file_id: str, requester: str, zk_proof: Dict[str, Any]) -> bool:
        """
        Evaluates access via Zero-Knowledge proof:
        Validates the prover's commitment without revealing the user's secret attributes on-chain.
        """
        if file_id not in self.files:
            raise ValueError("file not found")
        self._emit("ZkAccessRequested", fileId=file_id, requester=requester, commitment=zk_proof.get("commitment"))

        f = self.files[file_id]
        if f["revokedAll"]:
            self._emit("AccessDenied", fileId=file_id, requester=requester, reason="file access disabled by owner")
            return False

        # Verify zk-proof format & Fiat-Shamir challenge
        is_valid, msg = ZkAttributeProof.verify_proof(zk_proof, [zk_proof.get("commitment")])
        if not is_valid:
            self._emit("AccessDenied", fileId=file_id, requester=requester, reason=f"zk-proof invalid: {msg}")
            return False

        self.access[(file_id, requester)] = {
            "granted": True, "grantedAt": time.time(), "revokedAt": None,
        }
        self._emit("AccessGranted", fileId=file_id, requester=requester, verificationType="ZeroKnowledge")
        return True

    def can_access(self, file_id: str, user: str) -> bool:
        f = self.files.get(file_id)
        if not f or f["revokedAll"]:
            return False
        if user == f.get("owner"):
            return True
        state = self.access.get((file_id, user))
        if state and (not state.get("granted") or state.get("revokedAt") is not None):
            return False
        if user in f.get("authorizedUsers", []):
            return True
        if user in f.get("emergencyWhitelistedUsers", []):
            return bool(state and state.get("granted") and state.get("revokedAt") is None)
        return bool(state and state["granted"] and state["revokedAt"] is None)

    # -- Step 8: revocation -----------------------------------------------
    def revoke_access(self, file_id: str, user: str, caller: str):
        f = self.files.get(file_id)
        if not f:
            raise ValueError("file not found")
        if caller != f["owner"] and caller not in ["system_admin", "admin"]:
            raise PermissionError("not file owner")
        state = self.access.setdefault((file_id, user), {"granted": False, "grantedAt": None, "revokedAt": None})
        state["granted"] = False
        state["revokedAt"] = time.time()
        auth_users = f.get("authorizedUsers", [])
        if user in auth_users:
            auth_users.remove(user)
        self._emit("AccessRevoked", fileId=file_id, user=user)

    def revoke_all_access(self, file_id: str, caller: str):
        f = self.files.get(file_id)
        if not f:
            raise ValueError("file not found")
        if caller != f["owner"]:
            raise PermissionError("not file owner")
        f["revokedAll"] = True
        self._emit("AccessRevoked", fileId=file_id, user="ALL")

    def print_audit_log(self):
        print("\n--- On-chain audit log (Audit & Logging Module) ---")
        for i, e in enumerate(self.audit_log, 1):
            details = {k: v for k, v in e.items() if k not in ("event", "timestamp")}
            print(f"{i:2d}. {e['event']:<16} {details}")
