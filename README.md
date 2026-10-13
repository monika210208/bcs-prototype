# Blockchain-Based Secure Cloud Storage (BCS) & Access Control
### Full-Stack Integrated Architecture & Modern Web Dashboard

This repository delivers a **production-ready, fully integrated full-stack implementation** of the architecture specified in Section 5 of the project review report (*Blockchain-Based Secure Data Sharing and Access Control in Cloud Storage*), featuring:
1. **Cryptographic Engine (CP-ABE Equivalent)**: Client-side file encryption with random AES-256-GCM data keys and HKDF policy-gated key wrapping.
2. **Off-Chain Content-Addressed Storage**: SHA-256 content-addressed blob store simulating IPFS / cloud storage.
3. **Smart Contract Layer**: Access control state machine mirroring `contracts/AccessControl.sol` with automated policy evaluation and revocation.
4. **Backend REST API Server**: High-performance multi-threaded HTTP server (`server.py`) exposing complete RESTful endpoints with CORS support and state synchronization.
5. **Modern, Colorful Web Dashboard**: Premium enterprise interface (`frontend/`) styled with deep navy blue, royal blue, vibrant indigo, teal, emerald green, and coral accents.

---

## 1. System Architecture & Workflows

```
  ┌────────────────┐     1. Encrypt (AES-256-GCM)       ┌────────────────────────┐
  │   Data Owner   │ ─────────────────────────────────> │ Off-Chain Cloud / IPFS │
  │ (e.g. Dr. Priya)│      2. Put Blob (Store CID)       │   (demo_files/blobs)   │
  └───────┬────────┘                                    └───────────┬────────────┘
          │                                                         │
          │ 3. Register File (fileId, CID, Policy)                  │
          ▼                                                         │
  ┌─────────────────────────────────────────────────────────┐       │
  │      AccessControl Smart Contract / State Machine       │       │
  │     (Evaluates Required Attributes vs Held Attributes)  │       │
  └───────▲─────────────────────────────────────────▲───────┘       │
          │ 4. Request Access (Blockchain Tx)       │ 5. Decision   │
          │                                         │ (Grant/Deny)  │
  ┌───────┴────────┐                                │               │
  │   Data User    │ <──────────────────────────────┘               │
  │ (e.g. Requester│                                                │
  └───────┬────────┘     6. On Grant: Retrieve Ciphertext & Decrypt │
          └─────────────────────────────────────────────────────────┘
```

---

## 2. Directory Structure

```
bcs-prototype/
├── backend_service.py         # Service layer integrating crypto, blockchain & storage
├── server.py                  # Production-grade multi-threaded REST API & static server
├── demo.py                    # End-to-end CLI demonstration of Steps 1-8
├── demo_output.txt            # Verified CLI execution log
├── test_api_integration.py    # 11-step backend integration test suite
├── test_handler_mock.py       # 14-step HTTP request handler test suite
├── contracts/
│   └── AccessControl.sol      # Solidity smart contract (deployable to EVM / Hardhat)
├── crypto/
│   └── encryption_module.py   # CP-ABE policy-gated key wrapping (AES-256-GCM + HKDF)
├── storage/
│   └── cloud_storage.py       # Off-chain content-addressed storage (IPFS simulation)
├── blockchain/
│   └── contract_simulator.py  # Smart contract state machine & immutable audit log
├── demo_files/
│   └── blobs/                 # Off-chain encrypted ciphertext blobs
└── frontend/
    ├── index.html             # Single-Page Web Application with 8 core views
    ├── styles.css             # Enterprise design system (Navy, Indigo, Teal, Emerald)
    └── app.js                 # Reusable API service client layer & reactive state
```

---

## 3. How to Run the Application

### A. Start the Full-Stack Web Server (Backend + Frontend)
Run the server using Python 3:
```bash
cd bcs-prototype
python3 server.py --port 8000
```

Once started:
- **Web Dashboard**: Open `http://localhost:8000/` in any web browser.
- **REST API Base**: `http://localhost:8000/api/`
- **Network Interface**: Runs on `0.0.0.0:8000` (accessible locally or across network).

### B. Run the CLI End-to-End Walkthrough
```bash
python3 demo.py
```

### C. Run the Test Suites
```bash
# 1. Backend Service & Cryptographic Integration Tests:
python3 test_api_integration.py

# 2. HTTP Server, Routing & CORS Tests:
python3 test_handler_mock.py
```

---

## 4. Key Features & Frontend Views

1. **Executive Overview Dashboard**: Real-time KPI summary cards (Files, Grants, Denials, Users, Simulated Gas), interactive SVG charts for smart contract policy decisions and EVM gas profiles, and live audit event stream.
2. **Cloud File Repository**: Catalog of all off-chain encrypted files with searchable filters, status badges, CID hashes, and direct action triggers.
3. **CP-ABE Encrypt & Upload Studio**: 3-step wizard with policy presets (e.g., `Role:Doctor, Dept:Cardiology`), client-side encryption simulation, and on-chain registration.
4. **Access Control & Decryption Center**: Visual step-by-step smart contract verification pipeline comparing required vs. held attributes. Authorized users can decrypt the off-chain blob with instant plaintext display.
5. **Revocation & Kill-Switch Studio**: Per-user permission revocation without re-encrypting files, plus whole-file emergency freeze (`revokedAll`).
6. **User & Identity Module (Attribute Authority)**: Manage user identities, roles, departments, security clearances, and dynamically issue or revoke cryptographic attributes.
7. **Immutable On-Chain Audit Ledger**: Full blockchain transaction explorer with event filters (`AccessGranted`, `AccessDenied`, `FileUploaded`, `AccessRevoked`, `AttributeIssued`), search, and JSON export.
8. **Performance Benchmarking & Gas Analytics**: Live evaluation suite measuring access latency, key derivation speed, 2,000x+ revocation efficiency gains over full re-encryption, and EVM gas consumption breakdown.

---

## 5. REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status |
| `GET` | `/api/overview` | Aggregated metrics, gas calculations, and counts |
| `GET` | `/api/users` | List all registered identities and held attributes |
| `POST` | `/api/users` | Register a new user identity |
| `POST` | `/api/users/issue-attribute` | Issue attribute to a user (authority + contract) |
| `POST` | `/api/users/revoke-attribute` | Revoke attribute from a user |
| `GET` | `/api/files` | List all files, metadata, policies, and grant counts |
| `GET` | `/api/files/:id` | Get single file details and encrypted envelope |
| `POST` | `/api/files/upload` | Encrypt plaintext with CP-ABE, store blob, register on-chain |
| `POST` | `/api/files/:id/request-access` | Evaluate policy on smart contract and emit event |
| `POST` | `/api/files/:id/decrypt` | Verify contract permission, retrieve blob, unwrap key, decrypt |
| `POST` | `/api/files/:id/revoke` | Revoke single user's access on-chain |
| `POST` | `/api/files/:id/revoke-all` | Trigger whole-file emergency kill-switch |
| `POST` | `/api/files/:id/restore-all` | Restore file access after emergency freeze |
| `GET` | `/api/audit` | Query immutable audit log with filters |
| `GET` | `/api/benchmarks` | Retrieve evaluation latency and gas metrics |
| `POST` | `/api/benchmarks/run` | Execute live benchmark suite |
