#!/usr/bin/env python3
"""Migrate data from old DB to new DB without the UNIQUE constraint."""

import sys
import os
import sqlite3
from shutil import copy

sys.path.insert(0, os.path.dirname(__file__))

from app import app, db, BlockedThreat, User

try:
    print("[STEP 1] Creating new database with fresh schema...")
    with app.app_context():
        db.create_all()
        print("[OK] New database created")
    
    print("\n[STEP 2] Reading data from old database...")
    old_db = sqlite3.connect('instance/app.db.backup')
    old_cursor = old_db.cursor()
    
    # Get all threats from old DB
    old_cursor.execute("SELECT * FROM blocked_threat")
    old_columns = [desc[0] for desc in old_cursor.description]
    old_threats = old_cursor.fetchall()
    print(f"[OK] Found {len(old_threats)} threats in old database")
    print(f"    Columns: {old_columns}")
    
    old_db.close()
    
    print("\n[STEP 3] Importing data into new database...")
    with app.app_context():
        for threat_row in old_threats:
            threat_dict = dict(zip(old_columns, threat_row))
            
            # Skip ID to let SQLAlchemy auto-generate
            threat_dict.pop('id', None)
            
            # Create new threat
            new_threat = BlockedThreat(**threat_dict)
            db.session.add(new_threat)
        
        db.session.commit()
        print(f"[OK] Imported all {len(old_threats)} threats")
    
    print("\n[STEP 4] Verifying new database...")
    with app.app_context():
        count = BlockedThreat.query.count()
        print(f"[OK] New database has {count} threats")
        
        # Test unblocking
        test_threat = BlockedThreat.query.filter_by(is_active=True).first()
        if test_threat:
            print(f"[OK] Found active threat: {test_threat.ip_address}")
    
    print("\n[SUCCESS] Database migration complete!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
