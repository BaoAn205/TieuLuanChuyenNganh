"""Firestore persistence helpers for the FastAPI demo."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import firebase_admin
from firebase_admin import credentials, firestore
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
    counters = database.collection("system").document("counters")
    if not counters.get().exists:
        counters.set({"audit_event_id": 0, "transaction_id": 0})


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


def list_audit_events() -> list[dict[str, Any]]:
    rows = client().collection("audit_events").stream()
    return [row.to_dict() or {} for row in rows]


def get_audit_event(event_id: int) -> dict[str, Any] | None:
    snapshot = client().collection("audit_events").document(str(event_id)).get()
    return snapshot.to_dict() if snapshot.exists else None


def save_audit_event(event_id: int, values: dict[str, Any], *, merge: bool = True) -> None:
    client().collection("audit_events").document(str(event_id)).set(values, merge=merge)


def reserve_id(counter_name: str) -> int:
    database = client()
    reference = database.collection("system").document("counters")
    collection_name = {
        "audit_event_id": "audit_events",
        "transaction_id": "transactions",
    }.get(counter_name)
    # Counters may predate existing records or have been reset independently.
    # Start above the highest persisted numeric document ID to avoid collisions.
    highest_existing = 0
    if collection_name:
        for document in database.collection(collection_name).stream():
            try:
                highest_existing = max(highest_existing, int(document.id))
            except ValueError:
                continue
    transaction = database.transaction()

    @transactional
    def increment(transactional_context: Any) -> int:
        snapshot = reference.get(transaction=transactional_context)
        values = snapshot.to_dict() if snapshot.exists else {}
        next_value = max(int(values.get(counter_name, 0)), highest_existing) + 1
        transactional_context.set(reference, {counter_name: next_value}, merge=True)
        return next_value

    return increment(transaction)


def transfer_atomic(
    *,
    user_id: str,
    source_id: str,
    target_id: str,
    amount: float,
    transaction_id: int,
    transaction_row: dict[str, Any],
    event: dict[str, Any],
) -> None:
    database = client()
    source_ref = database.collection("accounts").document(source_id)
    target_ref = database.collection("accounts").document(target_id)
    transaction_ref = database.collection("transactions").document(str(transaction_id))
    event_ref = database.collection("audit_events").document(str(event["event_id"]))
    transaction = database.transaction()

    @transactional
    def apply_transfer(transactional_context: Any) -> None:
        source_snapshot = source_ref.get(transaction=transactional_context)
        target_snapshot = target_ref.get(transaction=transactional_context)
        if not source_snapshot.exists or not target_snapshot.exists:
            raise ValueError("Tài khoản nguồn hoặc đích không tồn tại")
        source = source_snapshot.to_dict() or {}
        target = target_snapshot.to_dict() or {}
        if source.get("user_id") != user_id:
            raise PermissionError("Tài khoản nguồn không thuộc người dùng hiện tại")
        if float(source.get("balance", 0)) < amount:
            raise ValueError("Số dư không đủ")
        if source_id == target_id:
            raise ValueError("Không thể chuyển tiền vào tài khoản nguồn")
        transactional_context.update(source_ref, {"balance": float(source["balance"]) - amount})
        transactional_context.update(target_ref, {"balance": float(target.get("balance", 0)) + amount})
        transactional_context.create(transaction_ref, transaction_row)
        transactional_context.create(event_ref, event)

    apply_transfer(transaction)


def list_user_transactions(user_id: str) -> list[dict[str, Any]]:
    account_ids = {row["account_id"] for row in list_accounts(user_id)}
    rows = [
        row for row in list_transactions()
        if row.get("from_account") in account_ids or row.get("to_account") in account_ids
    ]
    return sorted(rows, key=lambda row: row.get("created_at", ""), reverse=True)
