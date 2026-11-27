"""Link pre-created Firebase Authentication users to migrated Firestore profiles."""

from __future__ import annotations

from firebase_admin import auth

from app.firestore_db import get_firestore_client


def main() -> None:
    db = get_firestore_client()
    profiles = list(db.collection("users").stream())
    auth_users = {}
    page = auth.list_users()
    while page:
        for account in page.users:
            if account.email:
                auth_users[account.email.lower()] = account
        page = page.get_next_page()

    linked = 0
    missing = []
    for profile in profiles:
        data = profile.to_dict() or {}
        email = str(data.get("email", "")).lower()
        account = auth_users.get(email)
        if not email or not account:
            missing.append(email or profile.id)
            continue
        if data.get("firebase_uid") != account.uid:
            profile.reference.update({"firebase_uid": account.uid})
            linked += 1

    print(f"Linked {linked} Firebase Auth account(s) to Firestore profile(s).")
    if missing:
        print("Create Firebase Authentication users for these profile emails first:")
        for value in missing:
            print(f"  - {value}")


if __name__ == "__main__":
    main()
