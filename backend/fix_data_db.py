#!/usr/bin/env python3
"""Remove the UNIQUE constraint from blocked_threat table in data.db."""

import sqlite3
import sys

db_path = 'instance/data.db'

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[STEP 1] Current schema:")
    schema = cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'").fetchone()
    print(schema[0])
    
    print("\n[STEP 2] Recreating table without UNIQUE constraint...")
    
    # SQLite doesn't support dropping constraints directly
    # We need to recreate the table
    
    # Step 1: Rename old table
    cursor.execute("ALTER TABLE blocked_threat RENAME TO blocked_threat_old")
    print("  Renamed old table to blocked_threat_old")
    
    # Step 2: Create new table WITHOUT the unique constraint
    cursor.execute("""
    CREATE TABLE blocked_threat (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        threat_type VARCHAR(100) NOT NULL,
        risk_category VARCHAR(20) NOT NULL,
        risk_score FLOAT NOT NULL,
        summary VARCHAR(500),
        blocked_by VARCHAR(20) NOT NULL,
        blocked_by_user_id INTEGER,
        reason VARCHAR(500),
        is_active BOOLEAN,
        blocked_at DATETIME,
        unblocked_at DATETIME,
        unblocked_by_user_id INTEGER,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        FOREIGN KEY(blocked_by_user_id) REFERENCES user (id),
        FOREIGN KEY(unblocked_by_user_id) REFERENCES user (id)
    )
    """)
    print("  Created new table WITHOUT unique constraint")
    
    # Step 3: Copy data from old to new
    cursor.execute("""
    INSERT INTO blocked_threat 
    SELECT * FROM blocked_threat_old
    """)
    print(f"  Copied data from old table")
    
    # Step 4: Drop old table
    cursor.execute("DROP TABLE blocked_threat_old")
    print("  Dropped old table")
    
    conn.commit()
    
    print("\n[STEP 3] Verifying new schema:")
    schema = cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'").fetchone()
    print(schema[0])
    
    # Verify data integrity
    count = cursor.execute("SELECT COUNT(*) FROM blocked_threat").fetchone()[0]
    print(f"\n[OK] Table now has {count} records")
    
    conn.close()
    print("\n[SUCCESS] Constraint removed successfully!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
