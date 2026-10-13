"""
demo.py
--------
End-to-end walkthrough of the architecture in Section 5 of the 50%
review report (Steps 1-8), using:
  - crypto/encryption_module.py   (Encryption Module, CP-ABE-equivalent)
  - storage/cloud_storage.py      (Cloud/IPFS Storage Module)
  - blockchain/contract_simulator.py  (Access-Control Smart Contract +
                                        Revocation + Audit modules)

Run:  python3 demo.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from crypto.encryption_module import AttributeAuthority, encrypt_file, decrypt_file
from storage.cloud_storage import put_blob, get_blob
from blockchain.contract_simulator import AccessControlSimulator


def section(title):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def main():
    contract = AccessControlSimulator()
    authority = AttributeAuthority()

    # ---- Setup: attribute authority issues attributes to two users ----
    section("SETUP — attribute authority issues attributes")
    for user, attr in [
        ("dr_priya", "Role:Doctor"), ("dr_priya", "Dept:Cardiology"),
        ("nurse_arjun", "Role:Nurse"), ("nurse_arjun", "Dept:Cardiology"),
    ]:
        authority.issue_attribute(user, attr)
        contract.issue_attribute(user, attr)
        print(f"  issued '{attr}' to {user}")

    # ---- Step 1-2: owner encrypts file, uploads ciphertext off-chain ----
    section("STEP 1-2 — owner encrypts file & uploads to off-chain storage")
    policy = ["Role:Doctor", "Dept:Cardiology"]
    plaintext = b"Patient record 48213: diagnosis, treatment plan, prescription history."

    envelope = encrypt_file(plaintext, policy, authority)
    print(f"  policy: {policy}")
    print(f"  file ciphertext (hex, truncated): {envelope['file_ciphertext'][:60]}...")

    blob_bytes = str(envelope).encode()  # what actually gets stored off-chain
    content_hash = put_blob(blob_bytes)
    print(f"  stored off-chain, content hash (IPFS-CID-equivalent): {content_hash[:16]}...")

    # ---- Step 3: register file + policy on-chain ----
    section("STEP 3 — register file hash + policy on-chain")
    file_id = "file_001"
    contract.upload_file(file_id, owner="dr_priya", content_hash=content_hash, required_attrs=policy)
    print(f"  fileId={file_id} recorded on-chain (owner=dr_priya, hash={content_hash[:16]}...)")

    # ---- Step 4-5: two users request access; contract evaluates policy ----
    section("STEP 4-5 — access requests, evaluated automatically by the contract")
    for requester in ("dr_priya", "nurse_arjun"):
        granted = contract.request_access(file_id, requester)
        print(f"  {requester} -> {'GRANTED' if granted else 'DENIED'}")

    # ---- Step 6: the granted user retrieves & decrypts ----
    section("STEP 6 — granted user retrieves ciphertext and decrypts locally")
    if contract.can_access(file_id, "dr_priya"):
        recovered = decrypt_file(envelope, "dr_priya", authority)
        print(f"  dr_priya decrypted: {recovered.decode()!r}")

    print("\n  nurse_arjun's attributes do not satisfy the policy (missing Role:Doctor),")
    print("  so nurse_arjun was denied on-chain in Step 5 and is never given ciphertext.")
    try:
        decrypt_file(envelope, "nurse_arjun", authority)
    except PermissionError as e:
        print(f"  (crypto layer independently enforces this too: {e})")

    # ---- Step 8: revocation, without re-uploading the file ----
    section("STEP 8 — owner revokes dr_priya's access")
    contract.revoke_access(file_id, "dr_priya", caller="dr_priya")
    print(f"  dr_priya can_access now: {contract.can_access(file_id, 'dr_priya')}")

    print("\n  Also revoking dr_priya's Dept:Cardiology attribute at the crypto layer")
    print("  (this is what a real re-encryption/rotation step would trigger):")
    authority.revoke_attribute("dr_priya", "Dept:Cardiology")
    try:
        decrypt_file(envelope, "dr_priya", authority)
    except PermissionError as e:
        print(f"  decrypt after revocation -> blocked: {e}")

    # ---- Step 7: full audit trail ----
    section("STEP 7 — full audit trail (Audit & Logging Module)")
    contract.print_audit_log()


if __name__ == "__main__":
    main()
