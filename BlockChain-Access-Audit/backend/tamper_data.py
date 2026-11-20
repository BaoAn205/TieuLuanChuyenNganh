"""Deliberately alter a Firestore audit record for the integrity demo."""

import argparse

from app.firestore_store import client


def main() -> None:
    parser = argparse.ArgumentParser(description="Alter one Firestore audit record for the tamper demo.")
    parser.add_argument("--event-id", type=int, required=True)
    parser.add_argument("--resource", default="/admin/secrets")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm deliberately modifying an audit record in Cloud Firestore.",
    )
    args = parser.parse_args()
    if not args.confirm:
        parser.error("This changes Firestore data. Add --confirm to continue.")

    reference = client().collection("audit_events").document(str(args.event_id))
    if not reference.get().exists:
        parser.error(f"Audit event #{args.event_id} was not found in Firestore.")
    reference.update({"resource": args.resource})
    print(f"Changed resource for Firestore audit event #{args.event_id}; its data_hash is unchanged.")


if __name__ == "__main__":
    main()
