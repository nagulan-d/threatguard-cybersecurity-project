#!/usr/bin/env python3
import sqlite3
import os

for db_file in ['app.db', 'data.db', 'threat_intelligence.db']:
    db_path = f'instance/{db_file}'
    print(f"\n[Checking {db_file}]")
    try:
        conn = sqlite3.connect(db_path)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"  Tables: {[t[0] for t in tables]}")
        
        if any('blocked' in t[0] for t in tables):
            for table_name in [t[0] for t in tables if 'blocked' in t[0]]:
                schema = conn.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}'").fetchone()
                print(f"  {table_name} schema:")
                print(f"    {schema[0]}")
        
        conn.close()
    except Exception as e:
        print(f"  Error: {e}")
