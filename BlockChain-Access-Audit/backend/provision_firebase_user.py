"""Create an application profile for an already-created Firebase Auth account."""

from __future__ import annotations

import argparse

from firebase_admin import auth

from app.firestore_db import get_firestore_client


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--full-name", required=True)
    parser.add_argument("--role", required=True, choices=["ADMIN", "STAFF", "AUDITOR", "CUSTOMER"])
    parser.add_argument("--wallet-address", required=True)
    parser.add_argument("--account-id")
    parser.add_argument("--initial-balance", type=int, default=0)
    args = parser.parse_args()

    db = get_firestore_client()
    firebase_user = auth.get_user_by_email(args.email)
    profile_ref = db.collection("users").document(args.user_id)
    if profile_ref.get().exists:
        parser.error(f"Firestore profile already exists: {args.user_id}")
    profile_ref.create({
        "user_id": args.user_id,
        "firebase_uid": firebase_user.uid,
        "email": firebase_user.email,
        "full_name": args.full_name,
        "role": args.role,
        "wallet_address": args.wallet_address,
    })
    if args.account_id:
        db.collection("accounts").document(args.account_id).create({
            "account_id": args.account_id,
            "user_id": args.user_id,
            "balance": args.initial_balance,
        })
    print(f"Provisioned {args.user_id} ({args.role}) for Firebase Auth UID {firebase_user.uid}.")


if __name__ == "__main__":
    main()
