// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AccessControl
/// @notice On-chain access-control layer for blockchain-based secure cloud file sharing.
///         Mirrors the architecture in Section 5 of the 50% review report:
///         the chain only ever stores small, cheap items -- file hashes, policies,
///         and events -- while the actual encrypted file lives off-chain (IPFS/cloud).
/// @dev    This contract implements the "Access-Control Smart Contract" and
///         "Revocation Module" from the module table, and doubles as the
///         "Audit & Logging Module" via emitted events.
contract AccessControl {

    // ---------------------------------------------------------------
    // Data structures
    // ---------------------------------------------------------------

    struct FileRecord {
        address owner;
        string  contentHash;      // IPFS CID / SHA-256 hash of the encrypted blob
        string[] requiredAttrs;   // policy: attributes a requester must hold, e.g. ["Role:Doctor","Dept:Cardiology"]
        bool    exists;
        bool    revokedAll;       // owner can kill-switch the whole file
    }

    struct AccessState {
        bool granted;
        uint256 grantedAt;
        uint256 revokedAt; // 0 while active
    }

    // fileId => record
    mapping(bytes32 => FileRecord) private files;

    // fileId => user => access state
    mapping(bytes32 => mapping(address => AccessState)) private access;

    // user => attribute => held?  (stand-in for an Attribute Authority / User & Identity Module)
    mapping(address => mapping(string => bool)) private userAttributes;

    address public attributeAuthority;

    // ---------------------------------------------------------------
    // Events  (this *is* the audit trail — Section 5, Step 7)
    // ---------------------------------------------------------------

    event FileUploaded(bytes32 indexed fileId, address indexed owner, string contentHash);
    event AccessRequested(bytes32 indexed fileId, address indexed requester);
    event AccessGranted(bytes32 indexed fileId, address indexed requester);
    event AccessDenied(bytes32 indexed fileId, address indexed requester, string reason);
    event AccessRevoked(bytes32 indexed fileId, address indexed requester);
    event AttributeIssued(address indexed user, string attribute);
    event AttributeRevoked(address indexed user, string attribute);

    // ---------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------

    modifier onlyOwnerOf(bytes32 fileId) {
        require(files[fileId].exists, "file not found");
        require(files[fileId].owner == msg.sender, "not file owner");
        _;
    }

    modifier onlyAttributeAuthority() {
        require(msg.sender == attributeAuthority, "not attribute authority");
        _;
    }

    constructor() {
        attributeAuthority = msg.sender;
    }

    // ---------------------------------------------------------------
    // User & Identity Module (simplified: attribute issuance)
    // ---------------------------------------------------------------

    function issueAttribute(address user, string calldata attribute) external onlyAttributeAuthority {
        userAttributes[user][attribute] = true;
        emit AttributeIssued(user, attribute);
    }

    function revokeAttribute(address user, string calldata attribute) external onlyAttributeAuthority {
        userAttributes[user][attribute] = false;
        emit AttributeRevoked(user, attribute);
    }

    function hasAttribute(address user, string calldata attribute) public view returns (bool) {
        return userAttributes[user][attribute];
    }

    // ---------------------------------------------------------------
    // Step 3: register an uploaded file + its access policy
    // ---------------------------------------------------------------

    function uploadFile(bytes32 fileId, string calldata contentHash, string[] calldata requiredAttrs) external {
        require(!files[fileId].exists, "fileId already used");
        files[fileId] = FileRecord({
            owner: msg.sender,
            contentHash: contentHash,
            requiredAttrs: requiredAttrs,
            exists: true,
            revokedAll: false
        });
        emit FileUploaded(fileId, msg.sender, contentHash);
    }

    // ---------------------------------------------------------------
    // Steps 4-5: request access, contract evaluates policy automatically
    // ---------------------------------------------------------------

    function requestAccess(bytes32 fileId) external {
        require(files[fileId].exists, "file not found");
        emit AccessRequested(fileId, msg.sender);

        FileRecord storage f = files[fileId];

        if (f.revokedAll) {
            emit AccessDenied(fileId, msg.sender, "file access disabled by owner");
            return;
        }

        for (uint256 i = 0; i < f.requiredAttrs.length; i++) {
            if (!userAttributes[msg.sender][f.requiredAttrs[i]]) {
                emit AccessDenied(fileId, msg.sender, "policy not satisfied");
                return;
            }
        }

        access[fileId][msg.sender] = AccessState({
            granted: true,
            grantedAt: block.timestamp,
            revokedAt: 0
        });
        emit AccessGranted(fileId, msg.sender);
    }

    function canAccess(bytes32 fileId, address user) external view returns (bool) {
        AccessState memory a = access[fileId][user];
        return a.granted && a.revokedAt == 0 && !files[fileId].revokedAll;
    }

    // ---------------------------------------------------------------
    // Step 8: revocation (per-user, or whole-file kill switch)
    // ---------------------------------------------------------------

    function revokeAccess(bytes32 fileId, address user) external onlyOwnerOf(fileId) {
        access[fileId][user].granted = false;
        access[fileId][user].revokedAt = block.timestamp;
        emit AccessRevoked(fileId, user);
    }

    function revokeAllAccess(bytes32 fileId) external onlyOwnerOf(fileId) {
        files[fileId].revokedAll = true;
        emit AccessRevoked(fileId, address(0)); // address(0) signals "all users"
    }

    function getFile(bytes32 fileId) external view returns (address owner, string memory contentHash, bool revokedAll) {
        FileRecord storage f = files[fileId];
        require(f.exists, "file not found");
        return (f.owner, f.contentHash, f.revokedAll);
    }
}
