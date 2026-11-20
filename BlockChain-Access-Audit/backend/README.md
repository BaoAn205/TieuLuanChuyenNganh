# Backend Integration and Tamper Demo

## Run the integration tests

The integration suite uses a temporary SQLite database and a local Ganache chain. The test fixture explicitly selects SQLite, so these tests do not access the Firestore project or change `database.db`.

From this directory:

```powershell
.\.venv-firestore\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv-firestore\Scripts\python.exe -m pytest -v tests\test_integration.py
```

The tests require Node.js/npm and the blockchain module's installed npm dependencies.

## Firestore backend

The application defaults to Cloud Firestore. It does not create users or accounts at startup. Create the initial administrator record in Firestore; administrators can create customer users and accounts from the Admin workspace. Customer passwords are hashed by the API before storage, and the API grants their on-chain role when blockchain mode is enabled. In the PowerShell window used to start FastAPI, set the Admin SDK credential path and Firebase project ID:

```powershell
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\to\firebase-service-account.json"
$env:GOOGLE_CLOUD_PROJECT = "your-firebase-project-id"
```

Then start the API:

```powershell
.\.venv-firestore\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Keep the service-account JSON outside the Git repository and never put it in frontend files. The backend uses Firebase Admin SDK, so Firestore security rules do not authenticate these server-side requests; protect the service-account key.

## Demonstrate audit tampering

Use a demo event ID displayed in the Audit Dashboard. This deliberately changes a record in Cloud Firestore without updating its hash:

```powershell
.\.venv-firestore\Scripts\python.exe .\tamper_data.py --event-id EVENT_ID --confirm
```

Verify the same event again in the dashboard; integrity verification should report a mismatch. This command modifies Firestore data, so use it only with a demo event.
