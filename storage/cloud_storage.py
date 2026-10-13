"""
storage/cloud_storage.py
--------------------------
Cloud/IPFS Storage Module (report Section 5, module table row 3).

In production this would push the encrypted blob to IPFS (or S3) and
return a real content identifier (CID) / object key. For this offline
prototype we simulate that exact interface locally: encrypted blobs are
written to disk under demo_files/blobs/, addressed by the SHA-256 hash
of their content -- which is precisely what an IPFS CID does
conceptually (content-addressed storage). Swapping in `ipfshttpclient`
or `boto3` (S3) later only changes `put_blob` / `get_blob`; nothing
upstream (encryption module, contract) needs to change.
"""

import os
import hashlib

BLOB_DIR = os.path.join(os.path.dirname(__file__), "..", "demo_files", "blobs")
os.makedirs(BLOB_DIR, exist_ok=True)


def put_blob(data: bytes) -> str:
    """Store bytes off-chain, return their content hash (stand-in for an IPFS CID)."""
    content_hash = hashlib.sha256(data).hexdigest()
    path = os.path.join(BLOB_DIR, content_hash)
    with open(path, "wb") as f:
        f.write(data)
    return content_hash


def get_blob(content_hash: str) -> bytes:
    path = os.path.join(BLOB_DIR, content_hash)
    if not os.path.exists(path):
        raise FileNotFoundError(f"blob {content_hash} not found in off-chain storage")
    with open(path, "rb") as f:
        return f.read()
