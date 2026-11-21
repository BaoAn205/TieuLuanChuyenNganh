import json
import hashlib
import hmac
import os
import secrets
import psycopg2
from psycopg2.extras import DictCursor
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput

try:
    from .crypto_utils import sha256
except ImportError:
    from crypto_utils import sha256

DATABASE_URL = os.getenv("DATABASE_URL", "")
ROLES = {"ADMIN", "STAFF", "AUDITOR", "CUSTOMER"}
ROLE_IDS = {"ADMIN": 1, "STAFF": 2, "AUDITOR": 3, "CUSTOMER": 4}
ACTIONS = {
    "LOGIN", "LOGOUT", "VIEW_ACCOUNT", "VIEW_TRANSACTION",
    "TRANSFER", "CHANGE_PROFILE", "ADMIN_ACCESS",
}
# Keep routine activity in PostgreSQL; anchor higher-impact actions on-chain.
ON_CHAIN_ACTIONS = {"TRANSFER", "CHANGE_PROFILE", "ADMIN_ACCESS"}
BLOCKCHAIN_ENABLED = os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true"
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8546")
BLOCKCHAIN_CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", "")
BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
        "name": "getRole",
        "outputs": [{"internalType": "enum AccessAndAudit.Role", "name": "", "type": "uint8"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "eventId", "type": "uint256"},
            {"internalType": "bytes32", "name": "userIdHash", "type": "bytes32"},
            {"internalType": "string", "name": "action", "type": "string"},
            {"internalType": "string", "name": "resource", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "string", "name": "result", "type": "string"},
            {"internalType": "bytes32", "name": "dataHash", "type": "bytes32"}
        ],
        "name": "recordAudit",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "eventId", "type": "uint256"},
            {"indexed": True, "internalType": "bytes32", "name": "userIdHash", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "actor", "type": "address"},
            {"indexed": False, "internalType": "string", "name": "action", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "resource", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "result", "type": "string"},
            {"indexed": False, "internalType": "bytes32", "name": "dataHash", "type": "bytes32"}
        ],
        "name": "AuditRecorded",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "eventId", "type": "uint256"},
            {"internalType": "bytes32", "name": "expectedDataHash", "type": "bytes32"}
        ],
        "name": "verifyAudit",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

app = FastAPI(title="Blockchain Access Audit API", version="1.0.0")


class DatabaseCursor:
    """Small compatibility layer for the existing qmark SQL and generated IDs."""
    def __init__(self, cursor):
        self._cursor = cursor
        self._cached_row = None

    def execute(self, query, parameters=()):
        self._cached_row = None
        query = query.replace("?", "%s")
        normalized = query.lstrip().upper()
        if normalized.startswith("INSERT INTO AUDIT_EVENTS"):
            query += " RETURNING event_id"
        elif normalized.startswith("INSERT INTO TRANSACTIONS"):
            query += " RETURNING transaction_id"
        self._cursor.execute(query, parameters)
        if " RETURNING " in query.upper():
            self._cached_row = self._cursor.fetchone()
        return self

    @property
    def lastrowid(self):
        return self._cached_row[0] if self._cached_row else None

    def fetchone(self):
        if self._cached_row is not None:
            row, self._cached_row = self._cached_row, None
            return row
        return self._cursor.fetchone()

    def fetchall(self):
        if self._cached_row is not None:
            row, self._cached_row = self._cached_row, None
            return [row, *self._cursor.fetchall()]
        return self._cursor.fetchall()

    def executemany(self, query, parameters):
        self._cursor.executemany(query.replace("?", "%s"), parameters)
        return self

    def __iter__(self):
        if self._cached_row is not None:
            row, self._cached_row = self._cached_row, None
            yield row
        yield from self._cursor


class DatabaseConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, query, parameters=()):
        return DatabaseCursor(self._connection.cursor(cursor_factory=DictCursor)).execute(query, parameters)

    def executemany(self, query, parameters):
        return DatabaseCursor(self._connection.cursor(cursor_factory=DictCursor)).executemany(query, parameters)

    def executescript(self, script):
        cursor = self._connection.cursor()
        cursor.execute(script)
        cursor.close()

    def __getattr__(self, name):
        return getattr(self._connection, name)


def connect() -> DatabaseConnection:
    if not DATABASE_URL:
        raise RuntimeError("Set DATABASE_URL to your PostgreSQL connection string")
    return DatabaseConnection(psycopg2.connect(DATABASE_URL))


def hash_password(password: str) -> str:
    iterations = 310_000
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    if not stored.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(password, stored)
    try:
        _, iterations, salt, expected = stored.split("$", 3)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def request_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def verify_wallet_role(wallet_address: str, role: str) -> None:
    if not Web3.is_address(wallet_address):
        raise HTTPException(401, "Connect a valid MetaMask wallet before signing in")
    if not BLOCKCHAIN_ENABLED:
        return
    if not BLOCKCHAIN_CONTRACT_ADDRESS:
        raise HTTPException(503, "Thiếu BLOCKCHAIN_CONTRACT_ADDRESS")
    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
    if not web3.is_connected():
        raise HTTPException(503, "Không kết nối được Blockchain RPC")
    contract_address = Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS)
    if not web3.eth.get_code(contract_address):
        raise HTTPException(
            503,
            "No smart contract is deployed at BLOCKCHAIN_CONTRACT_ADDRESS on the configured RPC. Redeploy after restarting Ganache and update the address.",
        )
    contract = web3.eth.contract(
        address=contract_address,
        abi=CONTRACT_ABI,
    )
    try:
        on_chain_role = contract.functions.getRole(
            Web3.to_checksum_address(wallet_address)
        ).call()
    except BadFunctionCallOutput as error:
        raise HTTPException(
            503,
            "Could not read getRole from the configured contract. Check that BLOCKCHAIN_CONTRACT_ADDRESS points to the deployed AccessAndAudit contract.",
        ) from error
    if on_chain_role != ROLE_IDS[role]:
        raise HTTPException(403, "Wallet role does not match this application account")


def init_db() -> None:
    if not DATABASE_URL:
        raise RuntimeError("Set DATABASE_URL to your PostgreSQL connection string")
    connection = connect()
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password TEXT NOT NULL,
            wallet_address TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            balance NUMERIC(18,2) NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount NUMERIC(18,2) NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            hash_version INTEGER NOT NULL DEFAULT 1,
            blockchain_tx_hash TEXT,
            blockchain_block_number INTEGER,
            blockchain_log_index INTEGER,
            details TEXT NOT NULL
        );
        """
    )
    connection.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_address TEXT NOT NULL DEFAULT ''")
    connection.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash_version INTEGER NOT NULL DEFAULT 1")
    connection.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS blockchain_tx_hash TEXT")
    connection.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS blockchain_block_number INTEGER")
    connection.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS blockchain_log_index INTEGER")
    connection.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at TEXT NOT NULL DEFAULT ''")
    connection.commit()
    connection.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_filter_time(value: str) -> str:
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError as error:
        raise HTTPException(400, "Thời gian lọc phải theo định dạng ISO 8601") from error


def get_current_user(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer session token is required")
    token = authorization.removeprefix("Bearer ").strip()
    connection = connect()
    user = connection.execute(
        """SELECT users.user_id, users.full_name, users.role, users.wallet_address, sessions.expires_at
        FROM sessions JOIN users USING (user_id) WHERE sessions.token = ?""",
        (token,),
    ).fetchone()
    connection.close()
    if user is None:
        raise HTTPException(401, "Session token is invalid")
    try:
        expired = datetime.fromisoformat(user["expires_at"]) <= datetime.now(timezone.utc)
    except (TypeError, ValueError):
        expired = True
    if expired:
        with connect() as cleanup:
            cleanup.execute("DELETE FROM sessions WHERE token = ?", (token,))
        raise HTTPException(401, "Session has expired; sign in again")
    return dict(user)


def ensure_user_access(current_user: dict[str, str], user_id: str) -> None:
    if current_user["user_id"] != user_id and current_user["role"] not in {"ADMIN", "STAFF"}:
        raise HTTPException(403, "Không có quyền truy cập tài khoản này")


def legacy_event_data_hash(user_id: str, action: str, resource: str,
                           details: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"userId": user_id, "action": action, "resource": resource, "details": details},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical)


def event_data_hash(event: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "eventId": event["eventId"],
            "userId": event["userId"],
            "role": event["role"],
            "action": event["action"],
            "resource": event["resource"],
            "timestamp": event["timestamp"],
            "sourceIp": event["sourceIp"],
            "result": event["result"],
            "riskLevel": event["riskLevel"],
            "details": event["details"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical)


def event_dict(row: Any | dict[str, Any]) -> dict[str, Any]:
    details = row["details"]
    if isinstance(details, str):
        details = json.loads(details)
    return {
        "eventId": row["event_id"],
        "userId": row["user_id"],
        "role": row["role"],
        "action": row["action"],
        "resource": row["resource"],
        "timestamp": row["timestamp"],
        "sourceIp": row["source_ip"],
        "result": row["result"],
        "riskLevel": row["risk_level"],
        "dataHash": row["data_hash"],
        "hashVersion": row["hash_version"],
        "blockchainTxHash": row["blockchain_tx_hash"],
        "blockchainBlockNumber": row["blockchain_block_number"],
        "blockchainLogIndex": row["blockchain_log_index"],
        "details": details,
    }


def record_on_blockchain(event: dict[str, Any]) -> dict[str, Any] | None:
    if not BLOCKCHAIN_ENABLED:
        return None
    if not BLOCKCHAIN_CONTRACT_ADDRESS or not BLOCKCHAIN_PRIVATE_KEY:
        raise HTTPException(503, "Thiếu BLOCKCHAIN_CONTRACT_ADDRESS hoặc BLOCKCHAIN_PRIVATE_KEY")

    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
    if not web3.is_connected():
        raise HTTPException(503, "Không kết nối được Blockchain RPC")

    account = web3.eth.account.from_key(BLOCKCHAIN_PRIVATE_KEY)
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS),
        abi=CONTRACT_ABI,
    )
    transaction = contract.functions.recordAudit(
        event["eventId"],
        bytes.fromhex(sha256(event["userId"])),
        event["action"],
        event["resource"],
        int(datetime.fromisoformat(event["timestamp"]).timestamp()),
        event["result"],
        bytes.fromhex(event["dataHash"]),
    ).build_transaction({
        "from": account.address,
        "nonce": web3.eth.get_transaction_count(account.address),
        "chainId": web3.eth.chain_id,
        "gas": 500000,
        "gasPrice": web3.eth.gas_price,
    })
    signed = account.sign_transaction(transaction)
    transaction_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
    if receipt.status != 1:
        raise HTTPException(502, "Blockchain từ chối Audit Event")
    recorded_logs = contract.events.AuditRecorded().process_receipt(receipt)
    matching_logs = [
        log for log in recorded_logs
        if int(log["args"]["eventId"]) == event["eventId"]
    ]
    if len(matching_logs) != 1:
        raise HTTPException(502, "Không tìm thấy duy nhất AuditRecorded event trong receipt")
    return {
        "txHash": transaction_hash.hex(),
        "blockNumber": int(receipt.blockNumber),
        "logIndex": int(matching_logs[0]["logIndex"]),
    }


def add_event(connection: DatabaseConnection, user_id: str, action: str,
              resource: str, result: str, details: dict[str, Any],
              source_ip: str = "127.0.0.1") -> dict[str, Any]:
    user = connection.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if user is None:
        raise HTTPException(404, "Không tìm thấy user")
    if user["role"] not in ROLES or action not in ACTIONS:
        raise HTTPException(400, "Role hoặc action không hợp lệ")
    timestamp = now()
    source_ip = source_ip or "unknown"
    cursor = connection.execute(
        """INSERT INTO audit_events
        (user_id, role, action, resource, timestamp, source_ip, result, risk_level,
         data_hash, hash_version, blockchain_tx_hash, blockchain_block_number,
         blockchain_log_index, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, user["role"], action, resource, timestamp, source_ip,
         result, "UNASSESSED", "0" * 64, 2, None, None, None, json.dumps(details)),
    )
    event = {
        "eventId": cursor.lastrowid, "userId": user_id, "role": user["role"],
        "action": action, "resource": resource, "timestamp": timestamp,
        "sourceIp": source_ip, "result": result, "riskLevel": "UNASSESSED",
        "dataHash": "", "hashVersion": 2, "blockchainTxHash": None,
        "blockchainBlockNumber": None, "blockchainLogIndex": None, "details": details,
    }
    data_hash = event_data_hash(event)
    connection.execute(
        "UPDATE audit_events SET data_hash = ? WHERE event_id = ?",
        (data_hash, cursor.lastrowid),
    )
    event["dataHash"] = data_hash
    try:
        transaction_hash = (
            record_on_blockchain(event) if action in ON_CHAIN_ACTIONS else None
        )
    except Exception:
        connection.rollback()
        raise
    if transaction_hash:
        connection.execute(
            """UPDATE audit_events SET blockchain_tx_hash = ?,
            blockchain_block_number = ?, blockchain_log_index = ? WHERE event_id = ?""",
            (transaction_hash["txHash"], transaction_hash["blockNumber"],
             transaction_hash["logIndex"], cursor.lastrowid),
        )
        event["blockchainTxHash"] = transaction_hash["txHash"]
        event["blockchainBlockNumber"] = transaction_hash["blockNumber"]
        event["blockchainLogIndex"] = transaction_hash["logIndex"]
    return event


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/blockchain/blocks")
def blockchain_blocks(
    limit: int = Query(default=12, ge=1, le=50),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Read recent blocks from the configured local JSON-RPC node for the block viewer."""
    current_user = get_current_user(authorization)
    if current_user["role"] not in {"ADMIN", "STAFF", "AUDITOR"}:
        raise HTTPException(403, "Only ADMIN, STAFF, and AUDITOR can inspect blockchain blocks")
    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 5}))
    if not web3.is_connected():
        raise HTTPException(503, f"Cannot connect to blockchain RPC at {BLOCKCHAIN_RPC_URL}")
    latest = web3.eth.block_number
    first = max(0, latest - limit + 1)
    blocks = []
    for number in range(first, latest + 1):
        block = web3.eth.get_block(number, full_transactions=True)
        transactions = [{
            "hash": tx["hash"].hex(),
            "from": tx["from"],
            "to": tx["to"],
            "valueWei": str(tx["value"]),
        } for tx in block["transactions"]]
        blocks.append({
            "number": int(block["number"]),
            "hash": block["hash"].hex(),
            "parentHash": block["parentHash"].hex(),
            "timestamp": int(block["timestamp"]),
            "transactionCount": len(transactions),
            "transactions": transactions,
        })
    return {"chainId": int(web3.eth.chain_id), "latestBlock": latest, "blocks": blocks}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    return {
        "user": {
            "user_id": current_user["user_id"],
            "full_name": current_user["full_name"],
            "role": current_user["role"],
            "walletAddress": current_user["wallet_address"],
        },
        "expiresAt": current_user["expires_at"],
    }


@app.post("/api/login")
def login(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    connection = connect()
    user = connection.execute(
        "SELECT user_id, full_name, role, password, wallet_address FROM users WHERE user_id = ?",
        (payload.get("userId"),),
    ).fetchone()
    if user is None or not verify_password(payload.get("password", ""), user["password"]):
        connection.close()
        raise HTTPException(401, "Thông tin đăng nhập không đúng")
    wallet_address = str(payload.get("walletAddress", ""))
    if not user["wallet_address"] or wallet_address.lower() != user["wallet_address"].lower():
        connection.close()
        raise HTTPException(403, "Connected wallet is not assigned to this user")
    try:
        verify_wallet_role(wallet_address, user["role"])
    except Exception:
        connection.close()
        raise
    if not user["password"].startswith("pbkdf2_sha256$"):
        upgraded_password = hash_password(payload["password"])
        connection.execute(
            "UPDATE users SET password = ? WHERE user_id = ?",
            (upgraded_password, user["user_id"]),
        )
    session_token = secrets.token_urlsafe(32)
    created_at = now()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(timespec="seconds")
    connection.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (session_token, user["user_id"], created_at, expires_at),
    )
    audit = add_event(
        connection, user["user_id"], "LOGIN", "banking-session", "SUCCESS", {},
        request_ip(request),
    )
    connection.commit()
    connection.close()
    return {
        "user": {
            "user_id": user["user_id"], "full_name": user["full_name"],
            "role": user["role"], "walletAddress": wallet_address,
        },
        "sessionToken": session_token,
        "expiresAt": expires_at,
        "audit": audit,
    }


@app.post("/api/logout")
def logout(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    current_user = get_current_user(authorization)
    token = authorization.removeprefix("Bearer ").strip()
    connection = connect()
    add_event(
        connection, current_user["user_id"], "LOGOUT", "banking-session", "SUCCESS", {},
        request_ip(request),
    )
    connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
    connection.commit()
    connection.close()
    return {"status": "logged_out"}


@app.patch("/api/profile")
def change_profile(
    payload: dict[str, Any],
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    full_name = str(payload.get("fullName", "")).strip()
    if not full_name or len(full_name) > 100:
        raise HTTPException(400, "Tên hiển thị phải có từ 1 đến 100 ký tự")
    connection = connect()
    old_name = connection.execute(
        "SELECT full_name FROM users WHERE user_id = ?", (current_user["user_id"],)
    ).fetchone()["full_name"]
    connection.execute(
        "UPDATE users SET full_name = ? WHERE user_id = ?",
        (full_name, current_user["user_id"]),
    )
    audit = add_event(
        connection,
        current_user["user_id"],
        "CHANGE_PROFILE",
        "profile",
        "SUCCESS",
        {"oldFullName": old_name, "newFullName": full_name},
        request_ip(request),
    )
    connection.commit()
    connection.close()
    return {"user": {**current_user, "full_name": full_name}, "audit": audit}


@app.post("/api/admin/access")
def admin_access(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    if current_user["role"] != "ADMIN":
        raise HTTPException(403, "Chỉ ADMIN được truy cập khu vực quản trị")
    connection = connect()
    audit = add_event(
        connection, current_user["user_id"], "ADMIN_ACCESS", "admin-console", "SUCCESS", {},
        request_ip(request),
    )
    connection.commit()
    connection.close()
    return {"audit": audit}


@app.post("/api/admin/customers")
def create_customer(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    if current_user["role"] != "ADMIN":
        raise HTTPException(403, "Only ADMIN can create customer accounts")

    user_id = str(payload.get("userId", "")).strip()
    full_name = str(payload.get("fullName", "")).strip()
    password = str(payload.get("password", ""))
    wallet_address = str(payload.get("walletAddress", "")).strip()
    account_id = str(payload.get("accountId", "")).strip()
    balance = payload.get("initialBalance", 0)
    if not user_id or len(user_id) > 64 or not user_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "User ID must use letters, numbers, hyphens, or underscores")
    if not full_name or len(full_name) > 100:
        raise HTTPException(400, "Full name must contain 1 to 100 characters")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if not Web3.is_address(wallet_address):
        raise HTTPException(400, "Enter a valid wallet address")
    if not account_id or len(account_id) > 32:
        raise HTTPException(400, "Enter a valid account ID")
    if isinstance(balance, bool) or not isinstance(balance, (int, float)) or not 0 <= balance <= 1_000_000_000_000:
        raise HTTPException(400, "Initial balance must be a non-negative number")

    if BLOCKCHAIN_ENABLED:
        if not BLOCKCHAIN_CONTRACT_ADDRESS or not BLOCKCHAIN_PRIVATE_KEY:
            raise HTTPException(503, "Blockchain contract and admin private key must be configured")
        web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
        if not web3.is_connected():
            raise HTTPException(503, "Cannot connect to blockchain RPC")
        account = web3.eth.account.from_key(BLOCKCHAIN_PRIVATE_KEY)
        contract = web3.eth.contract(
            address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS),
            abi=[{
                "inputs": [
                    {"internalType": "address", "name": "account", "type": "address"},
                    {"internalType": "enum AccessAndAudit.Role", "name": "role", "type": "uint8"},
                    {"internalType": "bytes32", "name": "userIdHash", "type": "bytes32"},
                ],
                "name": "grantRole", "outputs": [], "stateMutability": "nonpayable", "type": "function",
            }, {
                "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
                "name": "getRole",
                "outputs": [{"internalType": "enum AccessAndAudit.Role", "name": "", "type": "uint8"}],
                "stateMutability": "view", "type": "function",
            }],
        )
        if contract.functions.getRole(account.address).call() != ROLE_IDS["ADMIN"]:
            raise HTTPException(503, "BLOCKCHAIN_PRIVATE_KEY must belong to an ADMIN wallet on this contract")
        try:
            tx = contract.functions.grantRole(
                Web3.to_checksum_address(wallet_address), ROLE_IDS["CUSTOMER"],
                bytes.fromhex(sha256(user_id)),
            ).build_transaction({
                "from": account.address,
                "nonce": web3.eth.get_transaction_count(account.address),
                "chainId": web3.eth.chain_id,
                "gas": 200000,
                "gasPrice": web3.eth.gas_price,
            })
            signed = account.sign_transaction(tx)
            tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status != 1:
                raise HTTPException(502, "Blockchain rejected customer role assignment")
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(502, f"Could not assign customer role: {error}") from error

    user = {
        "user_id": user_id, "full_name": full_name, "role": "CUSTOMER",
        "password": hash_password(password), "wallet_address": Web3.to_checksum_address(wallet_address),
    }
    account_row = {"account_id": account_id, "user_id": user_id, "balance": float(balance)}
    connection = connect()
    try:
        connection.execute(
            "INSERT INTO users (user_id, full_name, role, password, wallet_address) VALUES (?, ?, ?, ?, ?)",
            (user_id, full_name, "CUSTOMER", user["password"], user["wallet_address"]),
        )
        connection.execute(
            "INSERT INTO accounts (account_id, user_id, balance) VALUES (?, ?, ?)",
            (account_id, user_id, float(balance)),
        )
        connection.commit()
    except psycopg2.IntegrityError as error:
        connection.rollback()
        raise HTTPException(409, "User ID or account ID already exists") from error
    finally:
        connection.close()

    return {"user": {"user_id": user_id, "full_name": full_name, "role": "CUSTOMER"}, "account": account_row}


@app.get("/api/accounts/{user_id}")
def accounts(
    user_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    ensure_user_access(current_user, user_id)
    connection = connect()
    if connection.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,)).fetchone() is None:
        connection.close()
        raise HTTPException(404, "Không tìm thấy user")
    rows = connection.execute("SELECT account_id, balance FROM accounts WHERE user_id = ?", (user_id,)).fetchall()
    add_event(connection, user_id, "VIEW_ACCOUNT", "account", "SUCCESS", {}, request_ip(request))
    connection.commit()
    connection.close()
    return {"accounts": [dict(row) for row in rows]}


@app.get("/api/beneficiaries/{account_id}")
def beneficiary(account_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    get_current_user(authorization)
    connection = connect()
    row = connection.execute(
        """SELECT accounts.account_id, users.full_name
        FROM accounts JOIN users USING (user_id) WHERE accounts.account_id = ?""",
        (account_id.strip(),),
    ).fetchone()
    connection.close()
    if row is None:
        raise HTTPException(404, "Không tìm thấy tài khoản thụ hưởng")
    return {
        "accountId": row["account_id"],
        "accountName": row["full_name"],
        "bankName": "Bancollect Bank",
    }


@app.get("/api/transactions/{user_id}")
def transactions(
    user_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    ensure_user_access(current_user, user_id)
    connection = connect()
    rows = connection.execute(
        """SELECT * FROM transactions WHERE from_account IN
        (SELECT account_id FROM accounts WHERE user_id = ?) OR to_account IN
        (SELECT account_id FROM accounts WHERE user_id = ?) ORDER BY created_at DESC""",
        (user_id, user_id),
    ).fetchall()
    add_event(connection, user_id, "VIEW_TRANSACTION", "transactions", "SUCCESS", {}, request_ip(request))
    connection.commit()
    connection.close()
    return {"transactions": [dict(row) for row in rows]}


@app.post("/api/transactions/transfer")
def transfer(
    payload: dict[str, Any],
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    user_id, target_id, amount = payload.get("userId"), payload.get("toAccount"), payload.get("amount")
    current_user = get_current_user(authorization)
    if user_id:
        ensure_user_access(current_user, user_id)
    if not user_id or not target_id or not isinstance(amount, (int, float)) or amount <= 0:
        raise HTTPException(400, "userId, toAccount và amount hợp lệ là bắt buộc")
    connection = connect()
    locked_accounts = connection.execute(
        """SELECT * FROM accounts WHERE account_id = (
            SELECT account_id FROM accounts WHERE user_id = ? ORDER BY account_id LIMIT 1
        ) OR account_id = ? ORDER BY account_id FOR UPDATE""",
        (user_id, target_id),
    ).fetchall()
    accounts_by_id = {row["account_id"]: row for row in locked_accounts}
    source = next((row for row in locked_accounts if row["user_id"] == user_id), None)
    target = accounts_by_id.get(target_id)
    if source is None or target is None or source["balance"] < amount:
        connection.close()
        raise HTTPException(400, "Tài khoản đích không tồn tại hoặc số dư không đủ")
    if source["account_id"] == target_id:
        connection.close()
        raise HTTPException(400, "Không thể chuyển tiền vào tài khoản nguồn")
    created_at = now()
    connection.execute("UPDATE accounts SET balance = balance - ? WHERE account_id = ?", (amount, source["account_id"]))
    connection.execute("UPDATE accounts SET balance = balance + ? WHERE account_id = ?", (amount, target_id))
    cursor = connection.execute(
        "INSERT INTO transactions (from_account, to_account, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (source["account_id"], target_id, amount, "SUCCESS", created_at),
    )
    audit = add_event(
        connection, user_id, "TRANSFER", target_id, "SUCCESS",
        {"transactionId": cursor.lastrowid, "amount": amount}, request_ip(request),
    )
    connection.commit()
    connection.close()
    return {"transaction": {"transactionId": cursor.lastrowid, "status": "SUCCESS", "createdAt": created_at}, "audit": audit}


@app.get("/api/events")
@app.get("/api/audit/logs")
def events(
    authorization: str | None = Header(default=None),
    user_id: str | None = Query(default=None, alias="userId"),
    role: str | None = None,
    action: str | None = None,
    from_time: str | None = Query(default=None, alias="from"),
    to_time: str | None = Query(default=None, alias="to"),
    blockchain_status: str | None = Query(default=None, alias="blockchainStatus"),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    if current_user["role"] not in {"ADMIN", "STAFF", "AUDITOR"}:
        raise HTTPException(403, "Chỉ ADMIN, STAFF hoặc AUDITOR được xem audit logs")

    filters = []
    parameters: list[Any] = []
    for column, value in (
        ("user_id", user_id), ("role", role.upper() if role else None),
        ("action", action.upper() if action else None),
    ):
        if value:
            filters.append(f"{column} = ?")
            parameters.append(value)
    if from_time:
        filters.append("timestamp >= ?")
        parameters.append(normalize_filter_time(from_time))
    if to_time:
        filters.append("timestamp <= ?")
        parameters.append(normalize_filter_time(to_time))
    if blockchain_status == "recorded":
        filters.append("blockchain_tx_hash IS NOT NULL")
    elif blockchain_status == "offchain":
        filters.append("blockchain_tx_hash IS NULL")
    elif blockchain_status:
        raise HTTPException(400, "blockchainStatus phải là recorded hoặc offchain")
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    connection = connect()
    rows = connection.execute(
        f"SELECT * FROM audit_events {where_clause} ORDER BY timestamp DESC",
        parameters,
    ).fetchall()
    connection.close()
    records = [event_dict(row) for row in rows]
    return {"count": len(records), "events": records, "logs": records}


@app.get("/api/audit/my-logs")
def my_audit_logs(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    connection = connect()
    rows = connection.execute(
        "SELECT * FROM audit_events WHERE user_id = ? ORDER BY timestamp DESC",
        (current_user["user_id"],),
    ).fetchall()
    connection.close()
    records = [event_dict(row) for row in rows]
    return {"count": len(records), "events": records}


@app.get("/api/audit/logs/{event_id}")
def audit_detail(
    event_id: int,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    connection = connect()
    row = connection.execute(
        "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
    ).fetchone()
    connection.close()
    if row is None:
        raise HTTPException(404, "Không tìm thấy Audit Event")
    if current_user["role"] not in {"ADMIN", "STAFF", "AUDITOR"} and row["user_id"] != current_user["user_id"]:
        raise HTTPException(403, "Không có quyền xem Audit Event này")
    return {"event": event_dict(row)}


@app.post("/api/verify-integrity")
def verify_integrity(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    current_user = get_current_user(authorization)
    if current_user["role"] not in {"ADMIN", "STAFF", "AUDITOR", "CUSTOMER"}:
        raise HTTPException(403, "Không có quyền xác minh audit")
    event_id = payload.get("eventId")
    connection = connect()
    row = connection.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,)).fetchone()
    connection.close()
    if row is None:
        return {"verified": False, "message": "Không tìm thấy Audit Event"}
    if current_user["role"] == "CUSTOMER" and row["user_id"] != current_user["user_id"]:
        raise HTTPException(403, "Không có quyền xác minh Audit Event của tài khoản khác")
    details = row["details"] if isinstance(row["details"], dict) else json.loads(row["details"])
    if row["hash_version"] >= 2:
        recalculated_hash = event_data_hash(event_dict(row))
    else:
        recalculated_hash = legacy_event_data_hash(
            row["user_id"], row["action"], row["resource"], details
        )
    database_match = recalculated_hash == row["data_hash"]
    on_chain_match: bool | None = None
    if BLOCKCHAIN_ENABLED and row["blockchain_tx_hash"]:
        if not BLOCKCHAIN_CONTRACT_ADDRESS:
            raise HTTPException(503, "Thiếu BLOCKCHAIN_CONTRACT_ADDRESS")
        web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
        if not web3.is_connected():
            raise HTTPException(503, "Không kết nối được Blockchain RPC")
        contract = web3.eth.contract(
            address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS),
            abi=CONTRACT_ABI,
        )
        try:
            on_chain_match = contract.functions.verifyAudit(
                event_id, bytes.fromhex(recalculated_hash)
            ).call({"from": Web3.to_checksum_address(current_user["wallet_address"])})
        except Exception:
            on_chain_match = False
    verified = database_match and (on_chain_match is not False)
    message = "Hash khớp với dữ liệu và blockchain" if verified and on_chain_match else (
        "Hash khớp với dữ liệu off-chain" if verified else "Phát hiện dữ liệu bị can thiệp: Hash không khớp"
    )
    return {
        "verified": verified,
        "message": message,
        "storedHash": row["data_hash"],
        "recalculatedHash": recalculated_hash,
        "onChainVerified": on_chain_match,
        "event": event_dict(row),
    }


# Wrap the complete FastAPI app so CORS headers are also added to unhandled
# error responses. Otherwise browsers hide a server-side 500 as "Failed to fetch".
app = CORSMiddleware(
    app=app,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
