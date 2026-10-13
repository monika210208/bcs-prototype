"""
storage/database.py
-------------------
SQLite Persistent Database Engine:
Persists the blockchain ledger, user credentials, off-chain metadata,
and audit logs to disk (storage/bcs_ledger.db).
"""

import os
import sqlite3
import json
import time
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "bcs_ledger.db")


class BCSDatabase:
    """Thread-safe SQLite persistence engine for the Blockchain Cloud Storage system."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    role TEXT,
                    department TEXT,
                    clearance TEXT,
                    attributes TEXT NOT NULL,
                    did TEXT,
                    created_at REAL NOT NULL
                )
            """)
            # 2. Files & Policies Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    ipfs_cid TEXT,
                    required_attrs TEXT NOT NULL,
                    policy_expression TEXT,
                    file_type TEXT,
                    size_bytes INTEGER,
                    revoked_all INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    metadata_json TEXT
                )
            """)
            # 3. Access States & Revocations
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_states (
                    file_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    granted INTEGER NOT NULL,
                    granted_at REAL,
                    revoked_at REAL,
                    PRIMARY KEY (file_id, user_id)
                )
            """)
            # 4. Audit Log Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    user_id TEXT,
                    file_id TEXT,
                    details_json TEXT NOT NULL,
                    tx_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_user(self, user_dict: Dict[str, Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO users (user_id, name, email, role, department, clearance, attributes, did, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_dict["userId"],
                user_dict.get("name", user_dict["userId"]),
                user_dict.get("email", ""),
                user_dict.get("role", ""),
                user_dict.get("department", ""),
                user_dict.get("clearance", ""),
                json.dumps(user_dict.get("attributes", [])),
                user_dict.get("did", ""),
                user_dict.get("createdAt", time.time())
            ))
            conn.commit()

    def save_file(self, file_dict: Dict[str, Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO files (file_id, name, owner, content_hash, ipfs_cid, required_attrs, policy_expression, file_type, size_bytes, revoked_all, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_dict["fileId"],
                file_dict.get("name", file_dict["fileId"]),
                file_dict["owner"],
                file_dict["contentHash"],
                file_dict.get("ipfsCid", ""),
                json.dumps(file_dict.get("requiredAttrs", [])),
                file_dict.get("policyExpression", ""),
                file_dict.get("fileType", "text/plain"),
                file_dict.get("size", 0),
                1 if file_dict.get("revokedAll", False) else 0,
                file_dict.get("createdAt", time.time()),
                json.dumps(file_dict)
            ))
            conn.commit()

    def record_access_state(self, file_id: str, user_id: str, granted: bool, granted_at: Optional[float], revoked_at: Optional[float]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO access_states (file_id, user_id, granted, granted_at, revoked_at)
                VALUES (?, ?, ?, ?, ?)
            """, (file_id, user_id, 1 if granted else 0, granted_at, revoked_at))
            conn.commit()

    def log_audit_event(self, event_dict: Dict[str, Any], tx_hash: str):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO audit_events (event_type, timestamp, user_id, file_id, details_json, tx_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_dict.get("event", "UnknownEvent"),
                event_dict.get("timestamp", time.time()),
                event_dict.get("user") or event_dict.get("requester") or "",
                event_dict.get("fileId", ""),
                json.dumps(event_dict),
                tx_hash
            ))
            conn.commit()

    def get_audit_events_count(self) -> int:
        with self._get_connection() as conn:
            res = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
            return res[0] if res else 0


# Global database instance
BCS_DB = BCSDatabase()
