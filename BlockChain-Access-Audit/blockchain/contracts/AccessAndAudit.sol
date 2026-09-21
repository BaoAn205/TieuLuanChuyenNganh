// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

contract AccessAndAudit {
    // =========================================================
    // ROLES
    // =========================================================

    enum Role {
        NONE,
        ADMIN,
        STAFF,
        AUDITOR,
        CUSTOMER
    }

    // Wallet address => Role
    mapping(address => Role) private roles;

    // Customer wallet => hashed user ID
    mapping(address => bytes32) private customerUserIdHash;

    // =========================================================
    // AUDIT EVENT
    // =========================================================

    struct AuditEvent {
        uint256 eventId;
        bytes32 userIdHash;
        string action;
        string resource;
        uint256 timestamp;
        string result;
        bytes32 dataHash;
        address actor;
    }

    // eventId => AuditEvent
    mapping(uint256 => AuditEvent) private auditEvents;

    // Prevent duplicate event IDs
    mapping(uint256 => bool) private eventExists;

    // =========================================================
    // EVENTS
    // =========================================================

    event RoleGranted(
        address indexed account,
        Role role
    );

    event RoleRevoked(
        address indexed account,
        Role role
    );

    event AuditRecorded(
        uint256 indexed eventId,
        bytes32 indexed userIdHash,
        address indexed actor,
        string action,
        string resource,
        uint256 timestamp,
        string result,
        bytes32 dataHash
    );

    // =========================================================
    // MODIFIERS
    // =========================================================

    modifier onlyAdmin() {
        require(
            roles[msg.sender] == Role.ADMIN,
            "Access denied: ADMIN only"
        );
        _;
    }

    modifier canRecordAudit() {
        require(
            roles[msg.sender] == Role.ADMIN ||
            roles[msg.sender] == Role.STAFF,
            "Access denied: cannot record audit"
        );
        _;
    }

    modifier canReadAudit() {
        require(
            roles[msg.sender] == Role.ADMIN ||
            roles[msg.sender] == Role.STAFF ||
            roles[msg.sender] == Role.AUDITOR,
            "Access denied: cannot read audit"
        );
        _;
    }

    modifier canVerifyAudit() {
        require(
            roles[msg.sender] == Role.ADMIN ||
            roles[msg.sender] == Role.STAFF ||
            roles[msg.sender] == Role.AUDITOR ||
            roles[msg.sender] == Role.CUSTOMER,
            "Access denied: cannot verify audit"
        );
        _;
    }

    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    constructor() {
        // The deployer becomes the first ADMIN
        roles[msg.sender] = Role.ADMIN;

        emit RoleGranted(
            msg.sender,
            Role.ADMIN
        );
    }

    // =========================================================
    // ROLE MANAGEMENT
    // =========================================================

    function grantRole(
        address account,
        Role role,
        bytes32 userIdHash
    ) external onlyAdmin {
        require(
            account != address(0),
            "Invalid address"
        );

        require(
            role != Role.NONE,
            "Invalid role"
        );

        roles[account] = role;

        if (role == Role.CUSTOMER) {
            customerUserIdHash[account] = userIdHash;
        }

        emit RoleGranted(
            account,
            role
        );
    }

    function revokeRole(
        address account
    ) external onlyAdmin {
        require(
            account != address(0),
            "Invalid address"
        );

        Role oldRole = roles[account];

        require(
            oldRole != Role.NONE,
            "Account has no role"
        );

        roles[account] = Role.NONE;

        if (oldRole == Role.CUSTOMER) {
            customerUserIdHash[account] = bytes32(0);
        }

        emit RoleRevoked(
            account,
            oldRole
        );
    }

    // =========================================================
    // ROLE INFORMATION
    // =========================================================

    function getRole(
        address account
    ) external view returns (Role) {
        return roles[account];
    }

    function getCustomerUserIdHash(
        address account
    ) external view returns (bytes32) {
        require(
            roles[msg.sender] == Role.ADMIN ||
            roles[msg.sender] == Role.STAFF ||
            roles[msg.sender] == Role.AUDITOR ||
            msg.sender == account,
            "Access denied"
        );

        return customerUserIdHash[account];
    }

    // =========================================================
    // RECORD AUDIT
    // =========================================================

    function recordAudit(
        uint256 eventId,
        bytes32 userIdHash,
        string calldata action,
        string calldata resource,
        uint256 timestamp,
        string calldata result,
        bytes32 dataHash
    ) external canRecordAudit {
        require(
            !eventExists[eventId],
            "Audit event already exists"
        );

        require(
            eventId != 0,
            "Invalid event ID"
        );

        require(
            dataHash != bytes32(0),
            "Invalid data hash"
        );

        auditEvents[eventId] = AuditEvent({
            eventId: eventId,
            userIdHash: userIdHash,
            action: action,
            resource: resource,
            timestamp: timestamp,
            result: result,
            dataHash: dataHash,
            actor: msg.sender
        });

        eventExists[eventId] = true;

        emit AuditRecorded(
            eventId,
            userIdHash,
            msg.sender,
            action,
            resource,
            timestamp,
            result,
            dataHash
        );
    }

    // =========================================================
    // READ AUDIT
    // =========================================================

    function getAudit(uint256 eventId)
        external
        view
        canReadAudit
        returns (
            uint256,
            bytes32,
            string memory,
            string memory,
            uint256,
            string memory,
            bytes32,
            address
        )
    {
        require(eventExists[eventId], "Audit event does not exist");

        AuditEvent memory audit = auditEvents[eventId];

        return (
            audit.eventId,
            audit.userIdHash,
            audit.action,
            audit.resource,
            audit.timestamp,
            audit.result,
            audit.dataHash,
            audit.actor
        );
    }

    // =========================================================
    // CUSTOMER READ OWN AUDIT
    // =========================================================

    function getMyAudit(uint256 eventId)
        external
        view
        returns (
            uint256,
            bytes32,
            string memory,
            string memory,
            uint256,
            string memory,
            bytes32,
            address
        )
    {
        require(
            roles[msg.sender] == Role.CUSTOMER,
            "Customer access only"
        );

        require(
            eventExists[eventId],
            "Audit event does not exist"
        );

        require(
            auditEvents[eventId].userIdHash ==
            customerUserIdHash[msg.sender],
            "Access denied: not your audit"
        );

        AuditEvent memory audit = auditEvents[eventId];

        return (
            audit.eventId,
            audit.userIdHash,
            audit.action,
            audit.resource,
            audit.timestamp,
            audit.result,
            audit.dataHash,
            audit.actor
        );
    }

    // =========================================================
    // VERIFY AUDIT
    // =========================================================

    function verifyAudit(
        uint256 eventId,
        bytes32 expectedDataHash
    )
        external
        view
        canVerifyAudit
        returns (bool)
    {
        require(
            eventExists[eventId],
            "Audit event does not exist"
        );

        return auditEvents[eventId].dataHash == expectedDataHash;
    }

    // =========================================================
    // CHECK EXISTENCE
    // =========================================================

    function auditExists(
        uint256 eventId
    ) external view returns (bool) {
        return eventExists[eventId];
    }
}