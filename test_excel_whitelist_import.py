"""
End-to-End Verification Suite for Excel (.xlsx / .csv) Bulk Names Import for Whitelisting & Access.
Tests:
1. Sample Excel (.xlsx) generation and binary validity.
2. Native .xlsx OpenXML parsing with 'Names' column containing usernames & human full names.
3. CSV / text list of 'names alone' parsing.
4. Bulk Direct File Access grant using Excel-imported names.
5. Bulk Emergency Break-Glass Responder whitelisting using Excel-imported names.
6. Bulk Organization Member whitelisting using Excel-imported names.
7. Uploader Studio file upload with Excel-whitelisted usernames.
"""

import base64
import json
from pathlib import Path
from test_handler_mock import execute_request


def _req(method, path, payload=None):
    status, _, body = execute_request(method, path, payload)
    return status, json.loads(body.decode("utf-8"))


def run_tests():
    print("=== Running Excel Bulk Names Whitelist & Access Tests ===")

    # 1. Fetch Sample Excel (.xlsx)
    status, sample_res = _req("GET", "/api/utils/sample-whitelist-excel")
    assert status == 200 and sample_res.get("success") is True, f"Sample Excel failed: {sample_res}"
    xlsx_b64 = sample_res["contentBase64"]
    xlsx_bytes = base64.b64decode(xlsx_b64)
    assert xlsx_bytes[:2] == b"PK", "Generated .xlsx must be a valid OpenXML ZIP archive"

    # Save sample .xlsx to workspace so user has a ready-to-upload Excel file
    sample_path_1 = Path(__file__).resolve().parent / "whitelisted_usernames_sample.xlsx"
    sample_path_2 = Path(__file__).resolve().parent.parent / "whitelisted_usernames_sample.xlsx"
    sample_path_1.write_bytes(xlsx_bytes)
    sample_path_2.write_bytes(xlsx_bytes)
    print(f"[PASS] 1. Sample Excel (.xlsx) generated ({len(xlsx_bytes)} bytes) and saved to {sample_path_2.name}")

    # 2. Parse the .xlsx file via POST /api/utils/parse-excel-usernames
    status, parse_res = _req("POST", "/api/utils/parse-excel-usernames", {
        "filename": "whitelisted_usernames_sample.xlsx",
        "contentBase64": xlsx_b64,
        "defaultOrg": "Metro General Hospital"
    })
    assert status == 200 and parse_res.get("success") is True, f"Parse .xlsx failed: {parse_res}"
    usernames = parse_res["usernames"]
    assert "dr_priya" in usernames, f"Expected dr_priya in {usernames}"
    assert "nurse_arjun" in usernames, f"Expected nurse_arjun in {usernames}"
    assert "anita_desai" in usernames, f"Expected 'Anita Desai' -> 'anita_desai' in {usernames}"
    assert "dr_vikram_rao" in usernames, f"Expected 'Dr. Vikram Rao' -> 'dr_vikram_rao' in {usernames}"
    assert "names" not in usernames, "Header 'Names' should be automatically skipped"
    print(f"[PASS] 2. Native .xlsx parsed {parse_res['count']} names: {usernames}")

    # 3. Parse a CSV/Excel sheet with ONLY human names (no header row at all)
    csv_only_names = "Dr.Meera Nair\nRohan Kulkarni\ndr_chen\nKavya Krishnan\n"
    csv_b64 = base64.b64encode(csv_only_names.encode("utf-8")).decode("ascii")
    status, csv_res = _req("POST", "/api/utils/parse-excel-usernames", {
        "filename": "hospital_names_only.csv",
        "contentBase64": csv_b64,
        "defaultOrg": "Metro General Hospital"
    })
    assert status == 200 and csv_res.get("success") is True, f"CSV parse failed: {csv_res}"
    csv_users = csv_res["usernames"]
    assert csv_users == ["dr_meera_nair", "rohan_kulkarni", "dr_chen", "kavya_krishnan"], f"Unexpected CSV users: {csv_users}"
    print(f"[PASS] 3. Names-only CSV parsed & auto-provisioned: {csv_users}")

    # 4. Bulk Grant Direct File Access using comma-separated / Excel-imported list
    bulk_names_str = ", ".join(usernames)
    status, grant_res = _req("POST", "/api/files/file_001/grant-user", {
        "fileId": "file_001",
        "userId": bulk_names_str,
        "caller": "dr_priya"
    })
    assert status == 200 and grant_res.get("success") is True, f"Bulk file access grant failed: {grant_res}"
    assert grant_res.get("grantedCount", 0) >= 5, f"Expected >=5 granted users: {grant_res}"
    assert "anita_desai" in grant_res["authorizedUsers"]
    print(f"[PASS] 4. Bulk direct file access granted to {grant_res['grantedCount']} users on file_001")

    # Verify newly imported 'anita_desai' can directly decrypt file_001
    status, dec_res = _req("POST", "/api/files/file_001/decrypt", {
        "userId": "anita_desai"
    })
    assert status == 200 and dec_res.get("success") is True, f"anita_desai should be able to decrypt file_001: {dec_res}"
    print("[PASS] 5. Excel-imported user 'anita_desai' verified & decrypted file_001 on-chain")

    # 5. Bulk Whitelist Emergency Responders using Excel-imported names
    status, em_res = _req("POST", "/api/emergency/whitelist/add", {
        "fileId": "file_001",
        "username": "Kavya Krishnan, Vikram Reddy, er_triage_doc",
        "caller": "dr_priya"
    })
    assert status == 200 and em_res.get("success") is True, f"Bulk emergency whitelist failed: {em_res}"
    assert "kavya_krishnan" in em_res["whitelistedResponders"]
    assert "vikram_reddy" in em_res["whitelistedResponders"]
    print(f"[PASS] 6. Bulk emergency responders whitelisted: {em_res['addedUsers']}")

    # 6. Bulk Whitelist Organization Members using Excel-imported names
    status, org_res = _req("POST", "/api/organizations/org_hospital/members", {
        "userId": "Anita Desai, Vikram Reddy, Kavya Krishnan",
        "role": "Specialist",
        "clearance": "Level-4 Secret",
        "caller": "dr_priya"
    })
    assert status == 200 and org_res.get("success") is True, f"Bulk org member add failed: {org_res}"
    assert org_res.get("addedCount") == 3, f"Expected 3 added members: {org_res}"
    print(f"[PASS] 7. Bulk organization members whitelisted ({org_res['addedCount']} workers)")

    # 7. Uploader Studio File Upload with Excel-whitelisted usernames
    status, up_res = _req("POST", "/api/files/upload", {
        "fileName": "icu_excel_whitelist_test.txt",
        "description": "Uploaded with bulk Excel whitelisted names",
        "fileType": "Clinical Record",
        "owner": "dr_priya",
        "policy": ["Role:Doctor"],
        "content": "CONFIDENTIAL ICU REPORT FOR EXCEL WHITELISTED TEAM",
        "isBinary": False,
        "mimeType": "text/plain",
        "organizationId": "org_hospital",
        "importanceLevel": "High",
        "authorizedUsers": ["Suresh Babu", "nurse_arjun"],
        "emergencyWhitelist": ["Suresh Babu", "er_triage_doc"]
    })
    assert status in (200, 201) and up_res.get("fileId"), f"Upload with authorizedUsers failed: {up_res}"
    assert "suresh_babu" in up_res.get("authorizedUsers", []), f"Expected suresh_babu in {up_res}"
    assert "suresh_babu" in up_res.get("emergencyWhitelistedUsers", []), f"Expected suresh_babu in emergency whitelist: {up_res}"
    print(f"[PASS] 8. Uploader Studio registered file {up_res['fileId']} with Excel-whitelisted users: {up_res['authorizedUsers']}")

    print("\nALL EXCEL BULK WHITELIST & ACCESS TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
