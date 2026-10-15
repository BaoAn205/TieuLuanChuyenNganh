# Phase 1 Test Evidence

Evidence captured from the local workspace on 2026-10-06. Automated results are from isolated Ganache instances created by the integration fixture.

## Automated checks

| Check | Command | Result |
| --- | --- | --- |
| Smart contract unit tests | `cd blockchain; npm test` | 15 passing |
| Backend/blockchain integration | `cd backend; .\.venv\Scripts\python.exe -m pytest tests -q` | 9 passed |
| Frontend script syntax | `node --check js/app.js`, `audit.js`, `wallet.js` | Exit code 0 |
| Workspace diagnostics | VS Code diagnostics for changed Python, HTML, CSS, JavaScript and TypeScript files | No errors found |

Integration scenarios cover login and wallet-role checks, invalid password without session creation, transfer/audit storage, transaction/block/log-index mapping, receipt event linkage, log filters, customer-only logs/detail isolation, logout/session expiry, and hash match/mismatch after SQLite tampering.

## Manual evidence still to capture

The automated browser UI check confirmed the filter controls load at mobile width without horizontal overflow. A headed MetaMask approval and a full visual demo recording have not been captured yet. Before final presentation, capture:

1. MetaMask connected to Ganache Local (chain ID `31337`) and Customer/Admin login.
2. An Audit Dashboard row showing tx hash, block number, and log index; verify result MATCH.
3. The same event after running `backend/tamper_data.py`; verify result MISMATCH.
4. Customer access denied for another user's audit detail, while their own audit remains available.