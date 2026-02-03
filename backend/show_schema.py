#!/usr/bin/env python3
import sqlite3
conn = sqlite3.connect('instance/app.db')
result = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_threat'").fetchone()
if result:
    print(result[0])
else:
    print("Table not found in database")
    # List all tables
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    print("Available tables:", [t[0] for t in tables])
