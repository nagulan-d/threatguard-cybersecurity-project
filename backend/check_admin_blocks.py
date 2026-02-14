import sqlite3
from pathlib import Path

ROOT = Path(r"c:\Users\nagul\Downloads\Final_Project")
DB_PATHS = [
    ROOT / "backend" / "instance" / "data.db",
    ROOT / "instance" / "data.db",
]


def main():
    for path in DB_PATHS:
        if not path.exists():
            print(f"{path}: MISSING")
            continue
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM blocked_threat WHERE blocked_by='admin' AND is_active=1")
            count = cur.fetchone()[0]
            print(f"{path}: active admin blocks = {count}")
        except sqlite3.OperationalError as exc:
            print(f"{path}: ERROR - {exc}")
        finally:
            conn.close()


if __name__ == "__main__":
    main()
