import sqlite3
import json
from pathlib import Path
from app.firestore_db import get_firestore_client, is_firestore_enabled
from firebase_admin import firestore

DB_PATH = Path(__file__).resolve().parent / "database.db"


def migrate():
    print("==================================================")
    print("🔥 Đang kiểm tra kết nối Cloud Firestore...")
    print("==================================================")
    
    if not is_firestore_enabled():
        print("❌ Firestore chưa sẵn sàng. Cấu hình GOOGLE_APPLICATION_CREDENTIALS hoặc Application Default Credentials.")
        return

    db = get_firestore_client()
    print("✅ Đã kết nối thành công tới Firebase Cloud Firestore!\n")

    if not DB_PATH.exists():
        print(f"❌ Không tìm thấy file SQLite: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # 1. Migrate Users
    users = conn.execute("SELECT * FROM users").fetchall()
    print(f"👤 Đang đồng bộ {len(users)} người dùng...")
    for u in users:
        u_dict = dict(u)
        user_id = u_dict["user_id"]
        # Credentials belong to Firebase Authentication, never Firestore.
        # A delete sentinel also removes a password left by an older migration.
        u_dict["password"] = firestore.DELETE_FIELD
        # Thêm các trường mở rộng nếu chưa có
        u_dict.setdefault("email", f"{user_id}@banking-audit.edu.vn")
        u_dict.setdefault("firebase_uid", "")
        u_dict.setdefault("credit_limit", 50000000.0)
        u_dict.setdefault("loan_balance", 0.0)
        db.collection("users").document(user_id).set(u_dict, merge=True)
        print(f"   - User: {user_id} ({u_dict.get('role')})")

    # 2. Migrate Accounts
    accounts = conn.execute("SELECT * FROM accounts").fetchall()
    print(f"\n💳 Đang đồng bộ {len(accounts)} tài khoản ngân hàng...")
    for acc in accounts:
        acc_dict = dict(acc)
        account_id = acc_dict["account_id"]
        db.collection("accounts").document(account_id).set(acc_dict, merge=True)
        print(f"   - Account: {account_id} -> User {acc_dict.get('user_id')}, Số dư: {acc_dict.get('balance'):,} đ")

    # 3. Migrate Transactions
    txs = conn.execute("SELECT * FROM transactions").fetchall()
    print(f"\n💸 Đang đồng bộ {len(txs)} giao dịch chuyển tiền...")
    for tx in txs:
        tx_dict = dict(tx)
        tx_id = str(tx_dict["transaction_id"])
        db.collection("transactions").document(tx_id).set(tx_dict, merge=True)
    print(f"   - Đã đồng bộ {len(txs)} giao dịch thành công.")

    # 4. Migrate Audit Events
    events = conn.execute("SELECT * FROM audit_events").fetchall()
    print(f"\n🛡️ Đang đồng bộ {len(events)} nhật ký kiểm toán (Audit Events)...")
    for ev in events:
        ev_dict = dict(ev)
        event_id = str(ev_dict["event_id"])
        if isinstance(ev_dict.get("details"), str):
            try:
                ev_dict["details"] = json.loads(ev_dict["details"])
            except Exception:
                pass
        db.collection("audit_events").document(event_id).set(ev_dict, merge=True)
    print(f"   - Đã đồng bộ {len(events)} audit events thành công.")

    # Seed ID counters after imported rows to prevent new ID collisions.
    counter_ref = db.collection("system").document("counters")
    transaction = db.transaction()

    @firestore.transactional
    def seed_counters(tx):
        snapshot = next(tx.get(counter_ref), None)
        existing = (snapshot.to_dict() or {}) if snapshot and snapshot.exists else {}
        tx.set(counter_ref, {
            "audit_event_id": max(existing.get("audit_event_id", 0), max((int(row["event_id"]) for row in events), default=0)),
            "transaction_id": max(existing.get("transaction_id", 0), max((int(row["transaction_id"]) for row in txs), default=0)),
        }, merge=True)

    seed_counters(transaction)

    conn.close()
    print("\n==================================================")
    print("🎉 Hoàn tất đồng bộ toàn bộ dữ liệu lên Firebase Firestore!")
    print("==================================================")


if __name__ == "__main__":
    migrate()
