"""Deliberately alter a PostgreSQL audit record for the integrity demo."""

import argparse
import os

import psycopg2


def main() -> None:
    parser = argparse.ArgumentParser(description="Alter one PostgreSQL audit record for the tamper demo.")
    parser.add_argument("--event-id", type=int, required=True)
    parser.add_argument("--resource", default="/admin/secrets")
    parser.add_argument("--confirm", action="store_true", help="Confirm modifying an audit record.")
    args = parser.parse_args()
    if not args.confirm:
        parser.error("This changes PostgreSQL data. Add --confirm to continue.")
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        parser.error("Set DATABASE_URL before running this command.")
    with psycopg2.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_events SET resource = %s WHERE event_id = %s RETURNING event_id",
                (args.resource, args.event_id),
            )
            if cursor.fetchone() is None:
                parser.error(f"Audit event #{args.event_id} was not found in PostgreSQL.")
    print(f"Changed resource for PostgreSQL audit event #{args.event_id}; data_hash is unchanged.")


if __name__ == "__main__":
    main()
