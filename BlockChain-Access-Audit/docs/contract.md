# Smart Contract Handover

Source: `blockchain/contracts/AccessAndAudit.sol`  
Compiler: Solidity `0.8.34`; configured EVM target: Shanghai.  
Demo local chain: Ganache JSON-RPC `http://127.0.0.1:8546`, chain ID `31337`.

## Role identifiers

| Enum value | Role |
| ---: | --- |
| 0 | NONE |
| 1 | ADMIN |
| 2 | STAFF |
| 3 | AUDITOR |
| 4 | CUSTOMER |

## Functions and permissions

| Function | Permission | Behavior |
| --- | --- | --- |
| `grantRole(address, Role, bytes32)` | ADMIN | Assign role; associates a customer wallet with a hashed user ID |
| `revokeRole(address)` | ADMIN | Remove an existing role |
| `getRole(address)` | Public view | Return the wallet role |
| `getCustomerUserIdHash(address)` | ADMIN/STAFF/AUDITOR or the wallet itself | Return the customer's user ID hash |
| `recordAudit(eventId, userIdHash, action, resource, timestamp, result, dataHash)` | ADMIN/STAFF | Persist event and emit `AuditRecorded`; duplicate IDs and zero hashes are rejected |
| `getAudit(eventId)` | ADMIN/STAFF/AUDITOR | Return any existing audit event |
| `getMyAudit(eventId)` | CUSTOMER | Return only an event matching the caller's assigned user ID hash |
| `verifyAudit(eventId, expectedDataHash)` | Any assigned role | Compare expected hash with the event hash |
| `auditExists(eventId)` | Public view | Check whether an event ID exists |

## Events

- `RoleGranted(address indexed account, Role role)`
- `RoleRevoked(address indexed account, Role role)`
- `AuditRecorded(uint256 indexed eventId, bytes32 indexed userIdHash, address indexed actor, string action, string resource, uint256 timestamp, string result, bytes32 dataHash)`

## ABI and deployment

Hardhat compiler output contains the full ABI at `blockchain/artifacts/contracts/AccessAndAudit.sol/AccessAndAudit.json`. The backend keeps the small ABI fragment it uses for `getRole`, `recordAudit`, `verifyAudit`, and `AuditRecorded` in `backend/app/main.py`.

Start Ganache with `npm run node:ganache`; deploy and provision the four demo roles with `npm run deploy:local`. The printed address is specific to that Ganache chain instance and must be set as `BLOCKCHAIN_CONTRACT_ADDRESS`. Restarting Ganache resets its chain; redeploy and update the address after a reset.

## Development wallets

The demo uses Ganache's standard public test mnemonic to produce deterministic accounts 0-3. These keys are public development-only credentials; never use them with real funds or other networks.