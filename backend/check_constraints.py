#!/usr/bin/env python3
"""Fix UNIQUE constraint issue on blocked_threat table."""

import sys
import os
import sqlite3

sys.path.insert(0, os.path.dirname(__file__))

db_path = 'instance/app.db'

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[TABLE SCHEMA]")
    cursor.execute("PRAGMA table_info(blocked_threat)")
    for col in cursor.fetchall():
        print(f"  {col}")
    
    print("\n[INDEXES]")
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='blocked_threat'")
    for idx in cursor.fetchall():
        if idx[0]:  # SQL is not None
            print(f"  {idx[0]}")
    
    # Check the actual constraint
    print("\n[TABLE DEFINITION]")
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'")
    result = cursor.fetchone()
    if result:
        print(result[0])
    
    conn.close()
    print("\n[INFO] To fix the UNIQUE constraint issue, we need to recreate the table")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
