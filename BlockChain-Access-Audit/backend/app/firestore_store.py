"""Firestore persistence helpers for the FastAPI demo."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import FailedPrecondition
from google.cloud.firestore_v1 import transactional


def _project_id() -> str:
    return os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("FIREBASE_PROJECT_ID", "")


@lru_cache(maxsize=1)
def client() -> firestore.client:
    project_id = _project_id()
    if not project_id:
        raise RuntimeError("Set GOOGLE_CLOUD_PROJECT to your Firebase project ID")
    if not firebase_admin._apps:
        credential_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        credential = credentials.Certificate(credential_path) if credential_path else None
        firebase_admin.initialize_app(credential, {"projectId": project_id})
    return firestore.client()


def initialize() -> None:
    database = client()
    counter_ref = database.collection("system").document("counters")
    snapshot = counter_ref.get()
    current = snapshot.to_dict() or {}
    needs_seed = {
        name: collection
        for name, collection in (
            ("audit_event_id", "audit_events"),
            ("transaction_id", "transactions"),
        )
        if int(current.get(name, 0) or 0) <= 0
    }
    if not needs_seed:
        return

    # Reconcile counters once at startup using indexed top-document queries.
    # Previously reserve_id scanned every document on every event creation.
    highest = {
        name: _highest_numeric_id(database, collection, name)
        for name, collection in needs_seed.items()
    }
    transaction = database.transaction()

    @transactional
    def seed_counters(tx: Any) -> None:
        latest = counter_ref.get(transaction=tx)
        values = latest.to_dict() or {}
        updates = {
            name: max(int(values.get(name, 0) or 0), highest_id)
            for name, highest_id in highest.items()
        }
        if not latest.exists or any(values.get(name) != value for name, value in updates.items()):
            tx.set(counter_ref, updates, merge=True)

    seed_counters(transaction)


def _highest_numeric_id(database: Any, collection: str, field: str) -> int:
    rows = (
        database.collection(collection)
        .order_by(field, direction=firestore.Query.DESCENDING)
        .limit(1)
        .stream()
    )
    for row in rows:
        try:
            return int((row.to_dict() or {}).get(field, row.id))
        except (TypeError, ValueError):
            return 0
    return 0


def get_user(user_id: str) -> dict[str, Any] | None:
    snapshot = client().collection("users").document(user_id).get()
    return snapshot.to_dict() if snapshot.exists else None


def save_user(user_id: str, values: dict[str, Any], *, merge: bool = True) -> None:
    client().collection("users").document(user_id).set(values, merge=merge)


def create_customer(user: dict[str, Any], account: dict[str, Any]) -> None:
    database = client()
    batch = database.batch()
    batch.create(database.collection("users").document(user["user_id"]), user)
    batch.create(database.collection("accounts").document(account["account_id"]), account)
    batch.commit()


def get_session(token: str) -> dict[str, Any] | None:
    snapshot = client().collection("sessions").document(token).get()
    if not snapshot.exists:
        return None
    session = snapshot.to_dict() or {}
    user = get_user(session.get("user_id", ""))
    if user is None:
        return None
    return {**user, "expires_at": session.get("expires_at", ""), "token": token}


def save_session(token: str, values: dict[str, Any]) -> None:
    client().collection("sessions").document(token).set(values)


def delete_session(token: str) -> None:
    client().collection("sessions").document(token).delete()


def list_accounts(user_id: str) -> list[dict[str, Any]]:
    rows = client().collection("accounts").where("user_id", "==", user_id).stream()
    return sorted((row.to_dict() or {} for row in rows), key=lambda row: row["account_id"])


def get_account(account_id: str) -> dict[str, Any] | None:
    snapshot = client().collection("accounts").document(account_id).get()
    return snapshot.to_dict() if snapshot.exists else None


def get_beneficiary(account_id: str) -> dict[str, Any] | None:
    account = get_account(account_id)
    if account is None:
        return None
    user = get_user(account["user_id"])
    if user is None:
        return None
    return {"account_id": account["account_id"], "full_name": user["full_name"]}


def list_transactions() -> list[dict[str, Any]]:
    rows = client().collection("transactions").stream()
    return [row.to_dict() or {} for row in rows]


def list_audit_events(*, limit: int = 50, cursor: int | None = None) -> tuple[list[dict[str, Any]], int | None]:
    query = client().collection("audit_events").order_by(
        "event_id", direction=firestore.Query.DESCENDING
    )
    if cursor is not None:
        query = query.start_after({"event_id": int(cursor)})
    rows = list(query.limit(limit).stream())
    records = []
    for row in rows:
        item = row.to_dict() or {}
        item.setdefault("event_id", int(row.id))
        records.append(item)
    next_cursor = int(records[-1]["event_id"]) if len(records) == limit else None
    return records, next_cursor


def list_user_audit_events(
    user_id: str, *, limit: int = 50, cursor: int | None = None
) -> tuple[list[dict[str, Any]], int | None]:
    query = (
        client().collection("audit_events")
        .where("user_id", "==", user_id)
        .order_by("event_id", direction=firestore.Query.DESCENDING)
    )
    try:
        if cursor is not None:
            query = query.start_after({"event_id": int(cursor)})
        rows = list(query.limit(limit).stream())
        records = []
        for row in rows:
            item = row.to_dict() or {}
            item.setdefault("event_id", int(row.id))
            records.append(item)
        next_cursor = int(records[-1]["event_id"]) if len(records) == limit else None
        return records, next_cursor
    except FailedPrecondition as error:
        if "requires an index" not in str(error).lower():
            raise

    # Firestore requires a composite index for user_id + event_id ordering.
    # Until that index is deployed, query only this user's documents and page locally.
    rows = client().collection("audit_events").where("user_id", "==", user_id).stream()
    records = []
    for row in rows:
        item = row.to_dict() or {}
        try:
            item.setdefault("event_id", int(row.id))
            item["event_id"] = int(item["event_id"])
        except (TypeError, ValueError):
            continue
        if cursor is None or item["event_id"] < int(cursor):
            records.append(item)
    records.sort(key=lambda item: item["event_id"], reverse=True)
    has_more = len(records) > limit
    records = records[:limit]
    next_cursor = int(records[-1]["event_id"]) if has_more else None
    return records, next_cursor


def get_audit_event(event_id: int) -> dict[str, Any] | None:
    snapshot = client().collection("audit_events").document(str(event_id)).get()
    return snapshot.to_dict() if snapshot.exists else None


def get_transaction(transaction_id: int) -> dict[str, Any] | None:
    snapshot = client().collection("transactions").document(str(transaction_id)).get()
    return snapshot.to_dict() if snapshot.exists else None


def get_transfer_request(idempotency_key: str) -> dict[str, Any] | None:
    snapshot = client().collection("transfer_requests").document(idempotency_key).get()
    return snapshot.to_dict() if snapshot.exists else None


def save_audit_event(event_id: int, values: dict[str, Any], *, merge: bool = True) -> None:
    client().collection("audit_events").document(str(event_id)).set(values, merge=merge)


def reserve_ids(*counter_names: str) -> dict[str, int]:
    allowed = {"audit_event_id", "transaction_id"}
    if not counter_names or any(name not in allowed for name in counter_names):
        raise ValueError("Unsupported Firestore counter name")
    database = client()
    reference = database.collection("system").document("counters")
    transaction = database.transaction()

    @transactional
    def increment(transactional_context: Any) -> dict[str, int]:
        snapshot = reference.get(transaction=transactional_context)
        values = snapshot.to_dict() if snapshot.exists else {}
        allocated = {
            name: int(values.get(name, 0) or 0) + 1
            for name in dict.fromkeys(counter_names)
        }
        transactional_context.set(reference, allocated, merge=True)
        return allocated

    return increment(transaction)


def reserve_id(counter_name: str) -> int:
    return reserve_ids(counter_name)[counter_name]


def transfer_atomic(
    *,
    user_id: str,
    source_id: str,
    target_id: str,
    amount: float,
    expected_source_balance: float,
    expected_target_balance: float,
    transaction_id: int,
    transaction_row: dict[str, Any],
    event: dict[str, Any],
    idempotency_key: str,
    request_hash: str,
) -> dict[str, Any]:
    database = client()
    source_ref = database.collection("accounts").document(source_id)
    target_ref = database.collection("accounts").document(target_id)
    transaction_ref = database.collection("transactions").document(str(transaction_id))
    event_ref = database.collection("audit_events").document(str(event["event_id"]))
    idempotency_ref = database.collection("transfer_requests").document(idempotency_key)
    transaction = database.transaction()

    @transactional
    def apply_transfer(transactional_context: Any) -> dict[str, Any]:
        idempotency_snapshot = idempotency_ref.get(transaction=transactional_context)
        if idempotency_snapshot.exists:
            existing = idempotency_snapshot.to_dict() or {}
            if existing.get("request_hash") != request_hash:
                raise ValueError("Idempotency key was already used for a different transfer")
            return {
                "duplicate": True,
                "transaction_id": int(existing["transaction_id"]),
                "event_id": int(existing["event_id"]),
            }

        source_snapshot = source_ref.get(transaction=transactional_context)
        target_snapshot = target_ref.get(transaction=transactional_context)
        if not source_snapshot.exists or not target_snapshot.exists:
            raise ValueError("Tài khoản nguồn hoặc đích không tồn tại")
        source = source_snapshot.to_dict() or {}
        target = target_snapshot.to_dict() or {}
        source_balance = float(source.get("balance", 0))
        target_balance = float(target.get("balance", 0))
        if source_balance != expected_source_balance or target_balance != expected_target_balance:
            raise ValueError("Số dư đã thay đổi trong lúc xử lý; hãy tải lại và thử lại")
        for account_id, balance, account in (
            (source_id, source_balance, source),
            (target_id, target_balance, target),
        ):
            audited_balance = account.get("audited_balance")
            if audited_balance is not None and float(audited_balance) != balance:
                raise ValueError(
                    f"Số dư tài khoản {account_id} không khớp checkpoint đã audit; giao dịch bị từ chối"
                )
        if source.get("user_id") != user_id:
            raise PermissionError("Tài khoản nguồn không thuộc người dùng hiện tại")
        if source_balance < amount:
            raise ValueError("Số dư không đủ")
        if source_id == target_id:
            raise ValueError("Không thể chuyển tiền vào tài khoản nguồn")
        source_after = source_balance - amount
        target_after = target_balance + amount
        transactional_context.update(source_ref, {
            "balance": source_after, "audited_balance": source_after,
            "balance_audit_event_id": event["event_id"],
        })
        transactional_context.update(target_ref, {
            "balance": target_after, "audited_balance": target_after,
            "balance_audit_event_id": event["event_id"],
        })
        transactional_context.create(transaction_ref, transaction_row)
        transactional_context.create(event_ref, event)
        transactional_context.create(idempotency_ref, {
            "user_id": user_id,
            "request_hash": request_hash,
            "transaction_id": transaction_id,
            "event_id": int(event["event_id"]),
        })
        return {
            "duplicate": False,
            "transaction_id": transaction_id,
            "event_id": int(event["event_id"]),
        }

    return apply_transfer(transaction)


def list_user_transactions(user_id: str) -> list[dict[str, Any]]:
    account_ids = {row["account_id"] for row in list_accounts(user_id)}
    database = client()
    found: dict[str, dict[str, Any]] = {}
    for account_id in account_ids:
        for field in ("from_account", "to_account"):
            rows = database.collection("transactions").where(field, "==", account_id).stream()
            for row in rows:
                item = row.to_dict() or {}
                item.setdefault("transaction_id", int(row.id) if row.id.isdigit() else row.id)
                found[row.id] = item
    return sorted(found.values(), key=lambda row: row.get("created_at", ""), reverse=True)
