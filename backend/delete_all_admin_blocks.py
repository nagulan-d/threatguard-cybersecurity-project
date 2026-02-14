"""
Permanently DELETE all admin-blocked threats from the database.
This is a destructive operation - use with caution.
"""
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
        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        db_path = _resolve_sqlite_path(db_uri)
        
        if db_path:
            print(f"Using database: {db_path}")
        
        # Get all admin blocks (active AND inactive)
        all_admin_blocks = BlockedThreat.query.filter_by(blocked_by="admin").all()
        total = len(all_admin_blocks)
        
        if total == 0:
            print("No admin-blocked threats found in database.")
            _verify_and_delete_sqlite(db_path)
            return
        
        print(f"\n⚠️  WARNING: About to PERMANENTLY DELETE {total} admin-blocked threat records!")
        print("This includes both active and inactive blocks.")
        print("\nRecords to be deleted:")
        for block in all_admin_blocks[:10]:  # Show first 10
            status = "ACTIVE" if block.is_active else "INACTIVE"
            print(f"  - {block.ip_address} ({status}) - Blocked at {block.blocked_at}")
        if total > 10:
            print(f"  ... and {total - 10} more")
        
        # Also delete related action logs
        action_logs = ThreatActionLog.query.filter(
            ThreatActionLog.action.in_(['auto_block', 'unblock_admin_bulk'])
        ).all()
        log_count = len(action_logs)
        
        print(f"\nAlso deleting {log_count} related action log entries.")
        print("\nType 'DELETE' to confirm permanent deletion (or anything else to cancel):")
        
        try:
            confirmation = input().strip()
        except:
            confirmation = ""
        
        if confirmation != "DELETE":
            print("\n❌ Deletion cancelled. No changes made.")
            return
        
        # Proceed with deletion
        print("\n🗑️  Deleting records...")
        
        deleted_blocks = 0
        deleted_logs = 0
        unblock_attempts = 0
        
        # Delete action logs first (they reference blocked_threats)
        for log in action_logs:
            try:
                db.session.delete(log)
                deleted_logs += 1
            except Exception as e:
                print(f"Failed to delete log {log.id}: {e}")
        
        # Delete blocked threats
        for block in all_admin_blocks:
            try:
                # Attempt firewall unblock before deleting
                try:
                    success, msg = ip_blocker.unblock_ip(block.ip_address)
                    if success:
                        unblock_attempts += 1
                except Exception as e:
                    pass  # Ignore firewall errors
                
                db.session.delete(block)
                deleted_blocks += 1
            except Exception as e:
                print(f"Failed to delete block {block.id} ({block.ip_address}): {e}")
        
        # Commit all deletions
        db.session.commit()
        
        print(f"\n✅ Deletion complete!")
        print(f"   - Deleted {deleted_blocks} blocked threat records")
        print(f"   - Deleted {deleted_logs} action log entries")
        print(f"   - Attempted {unblock_attempts} firewall unblocks")
        
        # Verify deletion in SQLite
        _verify_and_delete_sqlite(db_path)


def _verify_and_delete_sqlite(db_path: Path | None) -> None:
    """Direct SQLite verification and cleanup."""
    if not db_path or not db_path.exists():
        print("\n⚠️  SQLite verification skipped (database path not found).")
        return
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    try:
        # Count remaining admin blocks
        cur.execute("SELECT COUNT(*) FROM blocked_threat WHERE blocked_by='admin'")
        remaining = cur.fetchone()[0]
        
        if remaining > 0:
            print(f"\n⚠️  SQLite shows {remaining} admin blocks still in database.")
            print("Performing direct SQL deletion...")
            
            # Get IPs before deletion for logging
            cur.execute("SELECT ip_address FROM blocked_threat WHERE blocked_by='admin' LIMIT 10")
            sample_ips = [row[0] for row in cur.fetchall()]
            print(f"Sample IPs to delete: {', '.join(sample_ips)}")
            
            # Direct SQL DELETE
            cur.execute("DELETE FROM blocked_threat WHERE blocked_by='admin'")
            deleted = cur.rowcount
            
            # Also clean up orphaned action logs
            cur.execute("DELETE FROM threat_action_log WHERE action IN ('auto_block', 'unblock_admin_bulk')")
            deleted_logs = cur.rowcount
            
            conn.commit()
            print(f"✅ Direct SQL deletion complete:")
            print(f"   - Deleted {deleted} blocked_threat records")
            print(f"   - Deleted {deleted_logs} action_log records")
        else:
            print("\n✅ SQLite verification: 0 admin blocks remain in database.")
    
    except Exception as e:
        print(f"\n❌ SQLite verification error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
