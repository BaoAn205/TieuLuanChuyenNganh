import argparse
import os
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "database.db"


def main() -> None:
    parser = argparse.ArgumentParser(description="Sửa resource để demo phát hiện audit bị can thiệp.")
    parser.add_argument("--event-id", type=int, required=True)
    parser.add_argument("--resource", default="/admin/secrets")
    parser.add_argument("--database", type=Path, default=Path(os.getenv("AUDIT_DB_PATH", DEFAULT_DB_PATH)))
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Xác nhận cố ý sửa dữ liệu audit trong SQLite.",
    )
    args = parser.parse_args()
    if not args.confirm:
        parser.error("Thao tác phá hoại có chủ đích; thêm --confirm để tiếp tục.")

    with sqlite3.connect(args.database) as connection:
        cursor = connection.execute(
            "UPDATE audit_events SET resource = ? WHERE event_id = ?",
            (args.resource, args.event_id),
        )
        if cursor.rowcount != 1:
            parser.error(f"Không tìm thấy duy nhất event #{args.event_id} trong {args.database}")
    print(f"Đã sửa resource của audit event #{args.event_id}; data_hash giữ nguyên để Verify phát hiện.")


if __name__ == "__main__":
    main()