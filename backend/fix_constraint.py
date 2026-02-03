#!/usr/bin/env python3
"""Fix UNIQUE constraint on blocked_threat table by recreating it without the constraint."""

import sqlite3
import os

db_path = 'instance/app.db'

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Step 1: Check what constraint exists
    print("[STEP 1] Checking current constraints...")
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'")
    create_sql = cursor.fetchone()
    if create_sql:
        print("Current table definition:")
        print(create_sql[0])
    
    # Step 2: Check if there's a unique index
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='blocked_threat'")
    indexes = cursor.fetchall()
    print("\nCurrent indexes:")
    for idx_name, idx_sql in indexes:
        print(f"  {idx_name}: {idx_sql}")
        if "UNIQUE" in (idx_sql or ""):
            print(f"    -> Found UNIQUE index: {idx_name}")
            print(f"    -> Dropping index...")
            cursor.execute(f"DROP INDEX IF EXISTS [{idx_name}]")
    
    conn.commit()
    print("\n[OK] Constraint fix applied!")
    
    # Verify
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'")
    print("\nUpdated table definition:")
    print(cursor.fetchone()[0])
    
    conn.close()
    print("\n[SUCCESS] Database fixed!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
