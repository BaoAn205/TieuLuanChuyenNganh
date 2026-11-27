"""Firestore repository used by the FastAPI application.

Firebase Authentication owns credentials and tokens. Firestore stores only the
application profile and banking/audit data; password material is never written.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
import hashlib
import json
from typing import Any

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIREBASE_AVAILABLE = True
except ImportError:  # Give the API a useful configuration error at runtime.
    firebase_admin = None
    credentials = None
    firestore = None
    FIREBASE_AVAILABLE = False

_db = None


def get_firestore_client():
    global _db
    if _db is not None:
        return _db
    if not FIREBASE_AVAILABLE:
        raise RuntimeError("firebase-admin chưa được cài đặt")

    project_id = os.getenv("FIREBASE_PROJECT_ID")
    credential_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("FIREBASE_CREDENTIALS_PATH")
    options = {"projectId": project_id} if project_id else None
    if not firebase_admin._apps:
        if credential_path:
            cred = credentials.Certificate(credential_path)
            firebase_admin.initialize_app(cred, options=options)
        else:
            # Supports Application Default Credentials on managed Google Cloud.
            firebase_admin.initialize_app(options=options)
    _db = firestore.client()
    return _db


def is_firestore_enabled() -> bool:
    try:
        get_firestore_client()
        return True
    except Exception:
        return False


def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    doc = get_firestore_client().collection("users").document(user_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data.setdefault("user_id", doc.id)
    return data


def get_user_by_firebase_uid(uid: str) -> dict[str, Any] | None:
    docs = (
        get_firestore_client().collection("users")
        .where("firebase_uid", "==", uid).limit(1).stream()
    )
    for doc in docs:
        data = doc.to_dict() or {}
        data.setdefault("user_id", doc.id)
        return data
    return None


def update_user(user_id: str, fields: dict[str, Any]) -> None:
    get_firestore_client().collection("users").document(user_id).update(fields)


def get_account(account_id: str) -> dict[str, Any] | None:
    doc = get_firestore_client().collection("accounts").document(account_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data.setdefault("account_id", doc.id)
    return data


def list_user_accounts(user_id: str) -> list[dict[str, Any]]:
    docs = get_firestore_client().collection("accounts").where("user_id", "==", user_id).stream()
    result = []
    for doc in docs:
        item = doc.to_dict() or {}
        item.setdefault("account_id", doc.id)
        result.append(item)
    return result


def find_user_by_account(account_id: str) -> dict[str, Any] | None:
    account = get_account(account_id)
    return get_user_by_id(account.get("user_id", "")) if account else None


def list_transactions_for_user(user_id: str, limit: int = 100) -> list[dict[str, Any]]:
    db = get_firestore_client()
    account_ids = [item["account_id"] for item in list_user_accounts(user_id)]
    found: dict[str, dict[str, Any]] = {}
    for field in ("from_account", "to_account"):
        for account_id in account_ids:
            docs = db.collection("transactions").where(field, "==", account_id).stream()
            for doc in docs:
                item = doc.to_dict() or {}
                item.setdefault("transaction_id", int(doc.id) if doc.id.isdigit() else doc.id)
                found[doc.id] = item
    return sorted(found.values(), key=lambda item: item.get("created_at", ""), reverse=True)[:limit]


def create_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    """Allocate a monotonic event ID and create the event atomically."""
    db = get_firestore_client()
    counter_ref = db.collection("system").document("counters")
    transaction = db.transaction()

    @firestore.transactional
    def allocate_and_create(tx):
        counter = next(tx.get(counter_ref), None)
        current = (counter.to_dict() or {}).get("audit_event_id", 0) if counter and counter.exists else 0
        event_id = int(current) + 1
        event_data = {**event, "event_id": event_id}
        event_data["data_hash"] = _event_hash(event_data)
        tx.set(counter_ref, {"audit_event_id": event_id}, merge=True)
        tx.create(db.collection("audit_events").document(str(event_id)), event_data)
        return event_data

    return allocate_and_create(transaction)


def _event_hash(event: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "eventId": event["event_id"], "userId": event["user_id"],
            "role": event["role"], "action": event["action"],
            "resource": event["resource"], "timestamp": event["timestamp"],
            "sourceIp": event["source_ip"], "result": event["result"],
            "riskLevel": event["risk_level"], "details": event["details"],
        },
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def update_audit_event(event_id: int, updates: dict[str, Any]) -> None:
    get_firestore_client().collection("audit_events").document(str(event_id)).update(updates)


def get_audit_event(event_id: int) -> dict[str, Any] | None:
    doc = get_firestore_client().collection("audit_events").document(str(event_id)).get()
    if not doc.exists:
        return None
    return doc.to_dict()


def list_audit_events(
    *, user_id: str | None = None, role: str | None = None,
    action: str | None = None, from_time: str | None = None,
    to_time: str | None = None, blockchain_status: str | None = None,
    limit: int = 100, offset: int = 0,
) -> list[dict[str, Any]]:
    """Filter and page demo audit data. Production scale should use indexed queries/cursors."""
    query = get_firestore_client().collection("audit_events")
    # A bounded scan keeps multi-filter behavior consistent without requiring
    # generated composite indexes for every combination in this prototype.
    docs = query.order_by("event_id", direction=firestore.Query.DESCENDING).limit(5000).stream()
    records = []
    for doc in docs:
        item = doc.to_dict() or {}
        item.setdefault("event_id", int(doc.id))
        if user_id and item.get("user_id") != user_id:
            continue
        if role and item.get("role") != role:
            continue
        if action and item.get("action") != action:
            continue
        if from_time and item.get("timestamp", "") < from_time:
            continue
        if to_time and item.get("timestamp", "") > to_time:
            continue
        recorded = bool(item.get("blockchain_tx_hash"))
        if blockchain_status == "recorded" and not recorded:
            continue
        status = item.get("blockchain_status", "RECORDED" if recorded else "OFFCHAIN")
        if blockchain_status == "offchain" and status != "OFFCHAIN":
            continue
        records.append(item)
    records.sort(key=lambda item: (item.get("timestamp", ""), item.get("event_id", 0)), reverse=True)
    return records[offset:offset + limit]


def create_transfer(
    *, user: dict[str, Any], source: dict[str, Any], target: dict[str, Any],
    amount: int, created_at: str, event: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Atomically update balances and create transaction + audit documents."""
    db = get_firestore_client()
    transaction = db.transaction()
    source_ref = db.collection("accounts").document(source["account_id"])
    target_ref = db.collection("accounts").document(target["account_id"])
    tx_counter_ref = db.collection("system").document("counters")

    @firestore.transactional
    def apply_transfer(tx):
        source_snapshot = next(tx.get(source_ref), None)
        target_snapshot = next(tx.get(target_ref), None)
        counter_snapshot = next(tx.get(tx_counter_ref), None)
        if not source_snapshot or not source_snapshot.exists or not target_snapshot or not target_snapshot.exists:
            raise ValueError("Tài khoản không tồn tại")
        source_data = source_snapshot.to_dict() or {}
        target_data = target_snapshot.to_dict() or {}
        if int(source_data.get("balance", 0)) < amount:
            raise ValueError("Số dư không đủ")
        counters = counter_snapshot.to_dict() if counter_snapshot and counter_snapshot.exists else {}
        counters = counters or {}
        transaction_id = int(counters.get("transaction_id", 0)) + 1
        event_id = int(counters.get("audit_event_id", 0)) + 1
        event_data = {**event, "event_id": event_id}
        event_data["data_hash"] = _event_hash(event_data)
        transaction_data = {
            "transaction_id": transaction_id,
            "from_account": source["account_id"],
            "to_account": target["account_id"],
            "amount": amount,
            "status": "SUCCESS",
            "created_at": created_at,
        }
        tx.update(source_ref, {"balance": int(source_data.get("balance", 0)) - amount})
        tx.update(target_ref, {"balance": int(target_data.get("balance", 0)) + amount})
        tx.set(tx_counter_ref, {"transaction_id": transaction_id, "audit_event_id": event_id}, merge=True)
        tx.create(db.collection("transactions").document(str(transaction_id)), transaction_data)
        tx.create(db.collection("audit_events").document(str(event_id)), event_data)
        return transaction_data, event_data

    return apply_transfer(transaction)
