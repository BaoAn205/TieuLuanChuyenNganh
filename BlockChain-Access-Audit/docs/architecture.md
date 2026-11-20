# System Architecture

## Request and audit flow

```text
Browser UI + MetaMask
  -> FastAPI password/session + wallet binding
  -> contract getRole(wallet) role check
  -> SQLite read/write + canonical Audit Event
  -> SHA-256(dataHash)
  -> Web3.py signs recordAudit transaction
  -> Ganache local Ethereum node
  -> Audit Dashboard verifies off-chain fields against dataHash and contract
```

The banking UI is a simulation. No external bank, card processor, real payment rail, or cryptocurrency is involved.

## Storage boundaries

### SQLite (off-chain)

Stores demo users, salted password hashes, sessions, account balances, simulated transactions, full audit rows, transaction hashes, block numbers and log indexes. Audit details stay off-chain.

### Smart contract (on-chain)

`AccessAndAudit.sol` stores `eventId`, a SHA-256 user ID hash, action, resource, timestamp, result, `dataHash`, and the transaction actor. It does not store passwords, account balances, names, or transaction details.

## Audit hash format

New records use hash version 2. The canonical JSON includes:

- `eventId`, `userId`, `role`, `action`, `resource`
- `timestamp`, `sourceIp`, `result`, `riskLevel`
- `details`

Keys are sorted and JSON separators are compact before SHA-256. `dataHash`, `blockchainTxHash`, and the internal hash version are excluded from the canonical payload. Existing rows are migrated as version 1 and continue to use the legacy canonical fields (`userId`, `action`, `resource`, `details`) so old records are not incorrectly reported as tampered.

All activity, including login/logout and routine views, remains in Firestore for operational history. Only `TRANSFER`, `CHANGE_PROFILE`, and `ADMIN_ACCESS` are anchored as individual blockchain transactions; role grant/revoke are recorded by the contract's role events. Verification recomputes the hash from the Firestore row. If the row has a blockchain transaction, the recomputed hash is also checked with contract `verifyAudit`. For off-chain-only rows, the API reports that only off-chain verification was possible.

The receipt's `AuditRecorded` log is parsed and matched by `eventId`; its transaction hash, block number and log index are stored on the same SQLite row. This enables DB-to-receipt tracing without guessing based on timestamp or user.

## Access control

The contract defines `ADMIN`, `STAFF`, `AUDITOR`, and `CUSTOMER`; only ADMIN can grant/revoke roles, ADMIN/STAFF can record audit, and ADMIN/STAFF/AUDITOR can read audit. Customer can read only its own audit through `getMyAudit`.

Login requires the MetaMask address assigned to the selected user and verifies its contract role before creating a session. The backend still writes audit records through one configured signer, so the on-chain `actor` is the backend signer rather than the end user's wallet; user identity is represented by `userIdHash`.

## Runtime configuration

| Variable | Purpose |
| --- | --- |
| `BLOCKCHAIN_ENABLED` | Set to `true` to send records to the chain |
| `BLOCKCHAIN_RPC_URL` | Local JSON-RPC endpoint, normally `http://127.0.0.1:8546` |
| `BLOCKCHAIN_CONTRACT_ADDRESS` | Address printed by the deploy script |
| `BLOCKCHAIN_PRIVATE_KEY` | Local development signer only; never use a funded/private production key |

Ganache is the local node used by the demo and integration tests. Hardhat compiles/tests/deploys through its HTTP network; Ethers.js is used by the deployment tooling and Python Web3.py sends backend transactions. The Ganache mnemonic is the standard local Hardhat development mnemonic so seeded wallet addresses are deterministic. Use only local development keys.
