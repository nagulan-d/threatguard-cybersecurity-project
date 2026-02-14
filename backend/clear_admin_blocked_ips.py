from datetime import datetime
import sqlite3
from pathlib import Path

from app import app, db, BlockedThreat, ThreatActionLog, User, ip_blocker


def _resolve_sqlite_path(uri: str) -> Path | None:
    if not uri.startswith("sqlite:///"):
        return None
    raw_path = uri.replace("sqlite:///", "", 1)
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path(app.instance_path) / path
    return path


def main():
    with app.app_context():
        admin_user = User.query.filter_by(role="admin").first()
        admin_id = admin_user.id if admin_user else None

        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        db_path = _resolve_sqlite_path(db_uri)
        if db_path:
            print(f"Using database: {db_path}")

        blocks = BlockedThreat.query.filter_by(blocked_by="admin", is_active=True).all()
        total = len(blocks)
        if total == 0:
            print("No active admin-blocked IPs found.")
            # Still verify the DB directly in case the ORM is pointing elsewhere
            _force_deactivate_if_needed(db_path, admin_id)
            return

        db_success = 0
        db_fail = 0
        unblock_success = 0
        unblock_fail = 0

        for block in blocks:
            try:
                block.is_active = False
                block.unblocked_at = datetime.utcnow()
                block.unblocked_by_user_id = admin_id
                db.session.add(block)

                log = ThreatActionLog(
                    user_id=block.user_id,
                    action="unblock_admin_bulk",
                    ip_address=block.ip_address,
                    threat_id=block.id,
                    performed_by_user_id=admin_id,
                    details="Bulk admin cleanup script"
                )
                db.session.add(log)
                db.session.commit()
                db_success += 1
            except Exception as exc:
                db.session.rollback()
                db_fail += 1
                print(f"DB update failed for {block.ip_address}: {exc}")
                continue

            try:
                success, message = ip_blocker.unblock_ip(block.ip_address)
                if success:
                    unblock_success += 1
                else:
                    unblock_fail += 1
                    print(f"Firewall unblock failed for {block.ip_address}: {message}")
            except Exception as exc:
                unblock_fail += 1
                print(f"Firewall unblock exception for {block.ip_address}: {exc}")

        print("\nAdmin block cleanup complete")
        print(f"Total active admin blocks: {total}")
        print(f"DB updates: success={db_success}, fail={db_fail}")
        print(f"Firewall unblocks: success={unblock_success}, fail={unblock_fail}")

        _force_deactivate_if_needed(db_path, admin_id)


def _force_deactivate_if_needed(db_path: Path | None, admin_id: int | None) -> None:
    if not db_path or not db_path.exists():
        print("SQLite verification skipped (database path not found).")
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM blocked_threat WHERE blocked_by='admin' AND is_active=1")
        remaining = cur.fetchone()[0]
        if remaining > 0:
            cur.execute(
                "UPDATE blocked_threat SET is_active=0, unblocked_at=? WHERE blocked_by='admin' AND is_active=1",
                (datetime.utcnow().isoformat(),)
            )
            conn.commit()
            print(f"Forced deactivation applied to {remaining} admin blocks in SQLite.")
        else:
            print("SQLite verification: 0 active admin blocks remain.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
