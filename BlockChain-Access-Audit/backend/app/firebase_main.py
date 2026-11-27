"""FastAPI application backed by Firebase Authentication and Cloud Firestore."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from web3 import Web3

try:
    import firebase_admin
    from firebase_admin import auth
    from . import firestore_db as store
    from .crypto_utils import sha256
except ImportError as error:
    raise RuntimeError("Cài backend dependencies, gồm firebase-admin, trước khi chạy API") from error

ROLES = {"ADMIN", "STAFF", "AUDITOR", "CUSTOMER"}
ROLE_IDS = {"ADMIN": 1, "STAFF": 2, "AUDITOR": 3, "CUSTOMER": 4}
ACTIONS = {
    "LOGIN", "LOGOUT", "VIEW_ACCOUNT", "VIEW_TRANSACTION", "TRANSFER",
    "CHANGE_PROFILE", "ADMIN_ACCESS",
}
BLOCKCHAIN_ENABLED = os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true"
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "")
BLOCKCHAIN_CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", "")
BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
TX_LOCK = threading.Lock()

CONTRACT_ABI = [
    {"inputs": [{"internalType": "address", "name": "account", "type": "address"}],
     "name": "getRole", "outputs": [{"internalType": "enum AccessAndAudit.Role", "name": "", "type": "uint8"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [
        {"internalType": "uint256", "name": "eventId", "type": "uint256"},
        {"internalType": "bytes32", "name": "userIdHash", "type": "bytes32"},
        {"internalType": "string", "name": "action", "type": "string"},
        {"internalType": "string", "name": "resource", "type": "string"},
        {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        {"internalType": "string", "name": "result", "type": "string"},
        {"internalType": "bytes32", "name": "dataHash", "type": "bytes32"}],
     "name": "recordAudit", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"anonymous": False, "inputs": [
        {"indexed": True, "internalType": "uint256", "name": "eventId", "type": "uint256"},
        {"indexed": True, "internalType": "bytes32", "name": "userIdHash", "type": "bytes32"},
        {"indexed": True, "internalType": "address", "name": "actor", "type": "address"},
        {"indexed": False, "internalType": "string", "name": "action", "type": "string"},
        {"indexed": False, "internalType": "string", "name": "resource", "type": "string"},
        {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        {"indexed": False, "internalType": "string", "name": "result", "type": "string"},
        {"indexed": False, "internalType": "bytes32", "name": "dataHash", "type": "bytes32"}],
     "name": "AuditRecorded", "type": "event"},
    {"inputs": [
        {"internalType": "uint256", "name": "eventId", "type": "uint256"},
        {"internalType": "bytes32", "name": "expectedDataHash", "type": "bytes32"}],
     "name": "verifyAudit", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "eventId", "type": "uint256"}],
     "name": "auditExists", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
     "stateMutability": "view", "type": "function"},
]

app = FastAPI(title="Blockchain Access Audit API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in os.getenv(
        "CORS_ALLOWED_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",") if item.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def request_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def db():
    try:
        return store.get_firestore_client()
    except Exception as error:
        raise HTTPException(503, f"Firestore chưa sẵn sàng: {error}") from error


def get_current_user(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Firebase ID token is required")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        store.get_firestore_client()  # Initializes the Firebase Admin app used by auth too.
    except Exception as error:
        raise HTTPException(503, f"Firebase Admin chưa sẵn sàng: {error}") from error
    try:
        claims = auth.verify_id_token(token, check_revoked=True)
    except Exception as error:
        raise HTTPException(401, "Firebase ID token không hợp lệ hoặc đã hết hạn") from error
    try:
        user = store.get_user_by_firebase_uid(str(claims["uid"]))
    except Exception as error:
        raise HTTPException(503, f"Không đọc được hồ sơ Firestore: {error}") from error
    if not user:
        raise HTTPException(403, "Tài khoản Firebase chưa được liên kết với hồ sơ ứng dụng")
    if user.get("role") not in ROLES:
        raise HTTPException(403, "Hồ sơ không có role hợp lệ")
    user["firebase_uid"] = claims["uid"]
    return user


def ensure_user_access(current_user: dict[str, Any], user_id: str) -> None:
    if current_user["user_id"] != user_id and current_user["role"] not in {"ADMIN", "STAFF"}:
        raise HTTPException(403, "Không có quyền truy cập tài khoản này")


def verify_wallet_role(wallet_address: str, role: str) -> None:
    if not Web3.is_address(wallet_address):
        raise HTTPException(401, "Hãy kết nối MetaMask trước khi đăng nhập")
    if not BLOCKCHAIN_ENABLED:
        return
    if not BLOCKCHAIN_CONTRACT_ADDRESS or not BLOCKCHAIN_RPC_URL:
        raise HTTPException(503, "Thiếu BLOCKCHAIN_CONTRACT_ADDRESS hoặc BLOCKCHAIN_RPC_URL")
    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 5}))
    if not web3.is_connected():
        raise HTTPException(503, "Không kết nối được Blockchain RPC")
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS), abi=CONTRACT_ABI
    )
    actual = contract.functions.getRole(Web3.to_checksum_address(wallet_address)).call()
    if actual != ROLE_IDS[role]:
        raise HTTPException(403, "Role của ví không khớp với tài khoản ứng dụng")


def event_data_hash(event: dict[str, Any]) -> str:
    canonical = json.dumps({
        "eventId": event["eventId"], "userId": event["userId"],
        "role": event["role"], "action": event["action"],
        "resource": event["resource"], "timestamp": event["timestamp"],
        "sourceIp": event["sourceIp"], "result": event["result"],
        "riskLevel": event["riskLevel"], "details": event["details"],
    }, sort_keys=True, separators=(",", ":"))
    return sha256(canonical)


def event_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "eventId": int(row.get("event_id", 0)),
        "userId": row.get("user_id"), "role": row.get("role"),
        "action": row.get("action"), "resource": row.get("resource"),
        "timestamp": row.get("timestamp"), "sourceIp": row.get("source_ip", "unknown"),
        "result": row.get("result"), "riskLevel": row.get("risk_level", "UNASSESSED"),
        "dataHash": row.get("data_hash"), "hashVersion": row.get("hash_version", 2),
        "blockchainTxHash": row.get("blockchain_tx_hash"),
        "blockchainBlockNumber": row.get("blockchain_block_number"),
        "blockchainLogIndex": row.get("blockchain_log_index"),
        "blockchainStatus": row.get("blockchain_status", "RECORDED" if row.get("blockchain_tx_hash") else "OFFCHAIN"),
        "blockchainError": row.get("blockchain_error"),
        "details": row.get("details", {}),
    }


def record_on_blockchain(event: dict[str, Any]) -> dict[str, Any]:
    if not BLOCKCHAIN_ENABLED:
        raise RuntimeError("Blockchain recording is disabled")
    if not BLOCKCHAIN_CONTRACT_ADDRESS or not BLOCKCHAIN_RPC_URL or not BLOCKCHAIN_PRIVATE_KEY:
        raise RuntimeError("Thiếu BLOCKCHAIN_RPC_URL, BLOCKCHAIN_CONTRACT_ADDRESS hoặc BLOCKCHAIN_PRIVATE_KEY")
    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 10}))
    if not web3.is_connected():
        raise RuntimeError("Không kết nối được Blockchain RPC")
    account = web3.eth.account.from_key(BLOCKCHAIN_PRIVATE_KEY)
    contract = web3.eth.contract(address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS), abi=CONTRACT_ABI)
    # A prior send may have succeeded even if the API timed out before saving
    # its receipt. Reconcile that state before trying to submit a duplicate ID.
    if contract.functions.auditExists(event["eventId"]).call():
        expected = bytes.fromhex(event["dataHash"])
        if not contract.functions.verifyAudit(event["eventId"], expected).call():
            raise RuntimeError("Event ID tồn tại trên chain nhưng hash không khớp")
        matches = contract.events.AuditRecorded().get_logs(
            from_block=0, to_block="latest", argument_filters={"eventId": event["eventId"]}
        )
        if len(matches) != 1:
            raise RuntimeError("Đã tìm thấy event trên chain nhưng không đối soát được receipt")
        chain_log = matches[0]
        return {
            "blockchain_tx_hash": chain_log["transactionHash"].hex(),
            "blockchain_block_number": int(chain_log["blockNumber"]),
            "blockchain_log_index": int(chain_log["logIndex"]),
            "blockchain_status": "RECORDED", "blockchain_error": None,
        }
    with TX_LOCK:
        nonce = web3.eth.get_transaction_count(account.address, "pending")
        transaction = contract.functions.recordAudit(
            event["eventId"], bytes.fromhex(sha256(event["userId"])),
            event["action"], event["resource"],
            int(datetime.fromisoformat(event["timestamp"]).timestamp()),
            event["result"], bytes.fromhex(event["dataHash"]),
        ).build_transaction({
            "from": account.address, "nonce": nonce, "chainId": web3.eth.chain_id,
            "gas": 500000, "gasPrice": web3.eth.gas_price,
        })
        signed = account.sign_transaction(transaction)
        tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status != 1:
        raise RuntimeError("Blockchain từ chối Audit Event")
    logs = contract.events.AuditRecorded().process_receipt(receipt)
    matches = [item for item in logs if int(item["args"]["eventId"]) == event["eventId"]]
    if len(matches) != 1:
        raise RuntimeError("Không tìm thấy AuditRecorded tương ứng trong receipt")
    return {"blockchain_tx_hash": tx_hash.hex(),
            "blockchain_block_number": int(receipt.blockNumber),
            "blockchain_log_index": int(matches[0]["logIndex"]),
            "blockchain_status": "RECORDED", "blockchain_error": None}


def finish_audit(raw_event: dict[str, Any]) -> dict[str, Any]:
    event = event_dict(raw_event)
    if not BLOCKCHAIN_ENABLED:
        return event
    try:
        updates = record_on_blockchain(event)
    except Exception as error:
        updates = {"blockchain_status": "PENDING", "blockchain_error": str(error)[:500]}
    try:
        store.update_audit_event(event["eventId"], updates)
        raw_event.update(updates)
    except Exception:
        # The persisted audit remains available for later reconciliation.
        raw_event["blockchain_status"] = "PENDING"
    return event_dict(raw_event)


def add_event(user: dict[str, Any], action: str, resource: str, result: str,
              details: dict[str, Any], source_ip: str) -> dict[str, Any]:
    if action not in ACTIONS:
        raise HTTPException(400, "Audit action không hợp lệ")
    raw = {
        "user_id": user["user_id"], "role": user["role"], "action": action,
        "resource": resource, "timestamp": now(), "source_ip": source_ip or "unknown",
        "result": result, "risk_level": "UNASSESSED", "data_hash": "",
        "hash_version": 2, "blockchain_tx_hash": None,
        "blockchain_block_number": None, "blockchain_log_index": None,
        "blockchain_status": "PENDING" if BLOCKCHAIN_ENABLED else "OFFCHAIN",
        "details": details,
    }
    try:
        raw = store.create_audit_event(raw)
    except Exception as error:
        raise HTTPException(503, f"Không ghi được audit event lên Firestore: {error}") from error
    return finish_audit(raw)


def normalize_filter_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError as error:
        raise HTTPException(400, "Thời gian lọc phải theo ISO 8601") from error


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        store.get_firestore_client()
        return {"status": "ok", "database": "firestore"}
    except Exception as error:
        raise HTTPException(503, f"Firestore chưa sẵn sàng: {error}") from error


@app.post("/api/login")
def login(payload: dict[str, Any], request: Request,
          authorization: str | None = Header(default=None)) -> dict[str, Any]:
    wallet = str(payload.get("walletAddress", ""))
    user = get_current_user(authorization)
    assigned_wallet = str(user.get("wallet_address", ""))
    if not assigned_wallet or wallet.lower() != assigned_wallet.lower():
        raise HTTPException(403, "Ví MetaMask chưa được gán cho tài khoản này")
    verify_wallet_role(wallet, user.get("role", ""))
    audit = add_event(user, "LOGIN", "banking-session", "SUCCESS", {}, request_ip(request))
    return {"user": public_user(user), "audit": audit}


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {"user_id": user.get("user_id"), "full_name": user.get("full_name", ""),
            "role": user.get("role"), "walletAddress": user.get("wallet_address", "")}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    return {"user": public_user(user)}


@app.post("/api/logout")
def logout(request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    user = get_current_user(authorization)
    add_event(user, "LOGOUT", "banking-session", "SUCCESS", {}, request_ip(request))
    try:
        auth.revoke_refresh_tokens(user["firebase_uid"])
    except Exception as error:
        raise HTTPException(503, f"Đã ghi logout nhưng không thu hồi được refresh token: {error}") from error
    return {"status": "logged_out"}


@app.patch("/api/profile")
def change_profile(payload: dict[str, Any], request: Request,
                   authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    full_name = str(payload.get("fullName", "")).strip()
    if not full_name or len(full_name) > 100:
        raise HTTPException(400, "Tên hiển thị phải có từ 1 đến 100 ký tự")
    old_name = user.get("full_name", "")
    try:
        store.update_user(user["user_id"], {"full_name": full_name})
    except Exception as error:
        raise HTTPException(503, f"Không cập nhật được hồ sơ: {error}") from error
    user["full_name"] = full_name
    audit = add_event(user, "CHANGE_PROFILE", "profile", "SUCCESS",
                      {"oldFullName": old_name, "newFullName": full_name}, request_ip(request))
    return {"user": public_user(user), "audit": audit}


@app.post("/api/admin/access")
def admin_access(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Chỉ ADMIN được truy cập khu vực quản trị")
    return {"audit": add_event(user, "ADMIN_ACCESS", "admin-console", "SUCCESS", {}, request_ip(request))}


@app.get("/api/accounts/{user_id}")
def accounts(user_id: str, request: Request,
             authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    ensure_user_access(user, user_id)
    if not store.get_user_by_id(user_id):
        raise HTTPException(404, "Không tìm thấy user")
    result = store.list_user_accounts(user_id)
    add_event(user, "VIEW_ACCOUNT", "account", "SUCCESS", {"targetUserId": user_id}, request_ip(request))
    return {"accounts": [{"account_id": item["account_id"], "balance": item.get("balance", 0)} for item in result]}


@app.get("/api/beneficiaries/{account_id}")
def beneficiary(account_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    get_current_user(authorization)
    user = store.find_user_by_account(account_id.strip())
    account = store.get_account(account_id.strip())
    if not user or not account:
        raise HTTPException(404, "Không tìm thấy tài khoản thụ hưởng")
    return {"accountId": account_id.strip(), "accountName": user.get("full_name", ""), "bankName": "Bancollect Bank"}


@app.get("/api/transactions/{user_id}")
def transactions(user_id: str, request: Request,
                 authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    ensure_user_access(user, user_id)
    items = store.list_transactions_for_user(user_id)
    add_event(user, "VIEW_TRANSACTION", "transactions", "SUCCESS", {"targetUserId": user_id}, request_ip(request))
    return {"transactions": items}


def validate_transfer(payload: dict[str, Any]) -> tuple[str, int]:
    target_id, amount = payload.get("toAccount"), payload.get("amount")
    if not isinstance(target_id, str) or not target_id.strip() or len(target_id) > 64:
        raise HTTPException(400, "toAccount là bắt buộc")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0 or amount > 9_000_000_000_000:
        raise HTTPException(400, "amount phải là số nguyên VND dương hợp lệ")
    return target_id.strip(), amount


@app.post("/api/transactions/transfer")
def transfer(payload: dict[str, Any], request: Request,
             authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    target_id, amount = validate_transfer(payload)
    source_accounts = store.list_user_accounts(user["user_id"])
    if not source_accounts:
        raise HTTPException(400, "Tài khoản nguồn không tồn tại")
    source = source_accounts[0]
    target = store.get_account(target_id)
    if not target:
        raise HTTPException(400, "Tài khoản đích không tồn tại")
    if source["account_id"] == target_id:
        raise HTTPException(400, "Không thể chuyển vào tài khoản nguồn")
    created_at = now()
    event = {
        "user_id": user["user_id"], "role": user["role"], "action": "TRANSFER",
        "resource": target_id, "timestamp": created_at, "source_ip": request_ip(request),
        "result": "SUCCESS", "risk_level": "UNASSESSED", "data_hash": "",
        "hash_version": 2, "blockchain_tx_hash": None,
        "blockchain_block_number": None, "blockchain_log_index": None,
        "blockchain_status": "PENDING" if BLOCKCHAIN_ENABLED else "OFFCHAIN",
        "details": {"amount": amount},
    }
    try:
        tx_doc, raw_event = store.create_transfer(
            user=user, source=source, target=target, amount=amount,
            created_at=created_at, event=event,
        )
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    except Exception as error:
        raise HTTPException(503, f"Không hoàn tất giao dịch Firestore: {error}") from error
    audit = finish_audit(raw_event)
    return {"transaction": {"transactionId": tx_doc["transaction_id"],
                             "status": tx_doc["status"], "createdAt": created_at}, "audit": audit}


@app.get("/api/events")
@app.get("/api/audit/logs")
def events(authorization: str | None = Header(default=None),
           user_id: str | None = Query(default=None, alias="userId"), role: str | None = None,
           action: str | None = None, from_time: str | None = Query(default=None, alias="from"),
           to_time: str | None = Query(default=None, alias="to"),
           blockchain_status: str | None = Query(default=None, alias="blockchainStatus"),
           limit: int = Query(default=100, ge=1, le=500),
           offset: int = Query(default=0, ge=0)) -> dict[str, Any]:
    user = get_current_user(authorization)
    if user["role"] not in {"ADMIN", "STAFF", "AUDITOR"}:
        raise HTTPException(403, "Chỉ ADMIN, STAFF hoặc AUDITOR được xem audit logs")
    if blockchain_status not in {None, "recorded", "offchain"}:
        raise HTTPException(400, "blockchainStatus phải là recorded hoặc offchain")
    try:
        rows = store.list_audit_events(
            user_id=user_id, role=role.upper() if role else None,
            action=action.upper() if action else None,
            from_time=normalize_filter_time(from_time), to_time=normalize_filter_time(to_time),
            blockchain_status=blockchain_status, limit=limit, offset=offset,
        )
    except Exception as error:
        raise HTTPException(503, f"Không đọc được audit logs: {error}") from error
    records = [event_dict(row) for row in rows]
    return {"count": len(records), "limit": limit, "offset": offset, "events": records, "logs": records}


@app.get("/api/audit/my-logs")
def my_audit_logs(authorization: str | None = Header(default=None),
                  limit: int = Query(default=100, ge=1, le=500),
                  offset: int = Query(default=0, ge=0)) -> dict[str, Any]:
    user = get_current_user(authorization)
    rows = store.list_audit_events(user_id=user["user_id"], limit=limit, offset=offset)
    records = [event_dict(row) for row in rows]
    return {"count": len(records), "limit": limit, "offset": offset, "events": records}


@app.get("/api/audit/logs/{event_id}")
def audit_detail(event_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    row = store.get_audit_event(event_id)
    if not row:
        raise HTTPException(404, "Không tìm thấy Audit Event")
    if user["role"] not in {"ADMIN", "STAFF", "AUDITOR"} and row.get("user_id") != user["user_id"]:
        raise HTTPException(403, "Không có quyền xem Audit Event này")
    return {"event": event_dict(row)}


@app.post("/api/audit/logs/{event_id}/retry-blockchain")
def retry_blockchain(event_id: int,
                     authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Chỉ ADMIN được chạy lại ghi blockchain")
    if not BLOCKCHAIN_ENABLED:
        raise HTTPException(409, "Blockchain đang tắt")
    row = store.get_audit_event(event_id)
    if not row:
        raise HTTPException(404, "Không tìm thấy Audit Event")
    if row.get("blockchain_tx_hash"):
        return {"event": event_dict(row), "status": "already_recorded"}
    try:
        updates = record_on_blockchain(event_dict(row))
        store.update_audit_event(event_id, updates)
        row.update(updates)
    except Exception as error:
        store.update_audit_event(event_id, {
            "blockchain_status": "PENDING", "blockchain_error": str(error)[:500]
        })
        raise HTTPException(503, f"Chưa ghi được lên blockchain: {error}") from error
    return {"event": event_dict(row), "status": "recorded"}


@app.post("/api/verify-integrity")
def verify_integrity(payload: dict[str, Any],
                     authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    try:
        event_id = int(payload.get("eventId"))
    except (TypeError, ValueError) as error:
        raise HTTPException(400, "eventId không hợp lệ") from error
    row = store.get_audit_event(event_id)
    if not row:
        return {"verified": False, "message": "Không tìm thấy Audit Event"}
    if user["role"] == "CUSTOMER" and row.get("user_id") != user["user_id"]:
        raise HTTPException(403, "Không có quyền xác minh Audit Event của tài khoản khác")
    event = event_dict(row)
    if int(row.get("hash_version", 2)) >= 2:
        recalculated = event_data_hash(event)
    else:
        legacy = json.dumps({"userId": row.get("user_id"), "action": row.get("action"),
                             "resource": row.get("resource"), "details": row.get("details", {})},
                            sort_keys=True, separators=(",", ":"))
        recalculated = sha256(legacy)
    db_match = recalculated == row.get("data_hash")
    on_chain: bool | None = None
    if row.get("blockchain_tx_hash") and BLOCKCHAIN_ENABLED:
        if not BLOCKCHAIN_RPC_URL or not BLOCKCHAIN_CONTRACT_ADDRESS:
            raise HTTPException(503, "Thiếu cấu hình Blockchain RPC hoặc contract")
        web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 5}))
        if not web3.is_connected():
            raise HTTPException(503, "Không kết nối được Blockchain RPC")
        contract = web3.eth.contract(address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS), abi=CONTRACT_ABI)
        try:
            on_chain = contract.functions.verifyAudit(event_id, bytes.fromhex(recalculated)).call(
                {"from": Web3.to_checksum_address(user.get("wallet_address", ""))})
        except Exception:
            on_chain = False
    verified = db_match and on_chain is not False
    message = ("Hash khớp với dữ liệu và blockchain" if verified and on_chain else
               "Hash khớp với dữ liệu off-chain" if verified else
               "Phát hiện dữ liệu bị can thiệp: hash không khớp")
    return {"verified": verified, "message": message, "storedHash": row.get("data_hash"),
            "recalculatedHash": recalculated, "onChainVerified": on_chain, "event": event}
