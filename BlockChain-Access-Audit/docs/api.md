# API Reference

Base URL: `http://127.0.0.1:8000`. Protected endpoints require `Authorization: Bearer <sessionToken>`. Sessions expire after 8 hours. Passwords are stored as PBKDF2-SHA256 hashes; existing plaintext demo passwords are upgraded after a successful login. Login also requires the assigned MetaMask wallet and, with blockchain enabled, verifies its role against the configured contract.

## Endpoints

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/health` | Public | API health |
| `POST` | `/api/login` | Public | Verify credentials, create session, audit `LOGIN` |
| `POST` | `/api/logout` | Authenticated | Audit `LOGOUT`, revoke current session |
| `PATCH` | `/api/profile` | Authenticated | Update own display name, audit `CHANGE_PROFILE` |
| `GET` | `/api/accounts/{user_id}` | Own user; ADMIN/STAFF may access another user | Return account(s), audit `VIEW_ACCOUNT` |
| `GET` | `/api/beneficiaries/{account_id}` | Authenticated | Resolve recipient account name and bank |
| `GET` | `/api/transactions/{user_id}` | Own user; ADMIN/STAFF may access another user | Return simulated transactions, audit `VIEW_TRANSACTION` |
| `POST` | `/api/transactions/transfer` | Authenticated | Simulate an internal transfer and audit `TRANSFER` |
| `POST` | `/api/admin/access` | ADMIN only | Audit `ADMIN_ACCESS` |
| `POST` | `/api/admin/customers` | ADMIN only | Create customer and account; hash password and grant on-chain role when enabled |
| `GET` | `/api/me` | Authenticated | Restore current user/role after frontend reload |
| `GET` | `/api/audit/my-logs` | Authenticated | Return only events owned by current user |
| `GET` | `/api/audit/logs?userId=&role=&action=&from=&to=&blockchainStatus=` | ADMIN/STAFF/AUDITOR | Filter audit list by owner, role, action, time range, and chain status |
| `GET` | `/api/audit/logs/{event_id}` | Owner or ADMIN/STAFF/AUDITOR | Return one event, enforce owner isolation |
| `GET` | `/api/events` | ADMIN/STAFF/AUDITOR | Compatibility alias for audit logs |
| `POST` | `/api/verify-integrity` | Authenticated | Recompute hash and, when present, compare with on-chain hash |

## Request examples

Login:

```json
{"userId":"<Firestore user ID>","password":"<password>","walletAddress":"0x..."}
```

Transfer:

```json
{"userId":"<signed-in user ID>","toAccount":"<recipient account ID>","amount":1000}
```

Verify:

```json
{"eventId":1}
```

## Response shapes

Successful login returns `user`, `sessionToken`, `expiresAt`, and the `LOGIN` audit event. A transfer returns `transaction` and `audit`; the audit object includes `eventId`, `dataHash`, and `blockchainTxHash` when blockchain recording is enabled.

Audit logs return both `logs` and `events` arrays for compatibility. Each event includes `eventId`, `userId`, `role`, `action`, `resource`, `timestamp`, `sourceIp`, `result`, `riskLevel`, `dataHash`, `hashVersion`, `blockchainTxHash`, and `details`.

New `LOGIN`, `LOGOUT`, `VIEW_ACCOUNT`, and `VIEW_TRANSACTION` events are stored off-chain only. `TRANSFER`, `CHANGE_PROFILE`, and `ADMIN_ACCESS` are anchored on-chain. When an event is on-chain, it also includes `blockchainBlockNumber` and `blockchainLogIndex`; the receipt's `AuditRecorded` log is matched by event ID before saving. `/api/audit/logs` accepts `userId`, `role`, `action`, `from`, `to`, and `blockchainStatus=recorded|offchain` query parameters. Customer access is limited to `/api/audit/my-logs` and owned event detail.

Integrity verification returns `verified`, `message`, `storedHash`, `recalculatedHash`, `onChainVerified`, and the event. `onChainVerified` is `null` for records without an on-chain transaction.

The transfer and banking endpoints are for demonstration only; they do not move real money.
