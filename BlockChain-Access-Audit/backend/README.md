# Backend Integration and Tamper Demo

## Run the integration tests

The tests use a temporary SQLite database, start a local Hardhat node, deploy a fresh contract, and exercise the API through FastAPI's test client. They do not alter `database.db`.

From this directory, install the development dependencies and run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -v tests\test_integration.py
```

The tests require Node.js/npm and the blockchain module's installed npm dependencies.

## Run the tamper-detection demo

1. Start Hardhat locally, deploy `AccessAndAudit`, configure `BLOCKCHAIN_ENABLED=true`, `BLOCKCHAIN_RPC_URL`, `BLOCKCHAIN_CONTRACT_ADDRESS`, and `BLOCKCHAIN_PRIVATE_KEY`, then start the FastAPI backend.
2. In the banking page, sign in as `customer-001` / `customer123` and view the account or submit a transfer. The backend saves the audit row and its transaction hash.
3. Open `audit.html`, sign in as `auditor-001` / `audit123`, and press **Verify Integrity** on the event. The status should report that the hash matches the blockchain.
4. From this directory, deliberately alter that event's `resource` in the demo database:

```powershell
.\.venv\Scripts\python.exe .\tamper_data.py --event-id 1 --resource /admin/secrets --confirm
```

Replace `1` with the event ID shown by the dashboard. Press **Verify Integrity** again; the dashboard should show a red tampering warning. This script intentionally changes the selected SQLite row, so use it only with demo data. Set `AUDIT_DB_PATH` or pass `--database` to select a different database.