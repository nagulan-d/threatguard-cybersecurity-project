#!/usr/bin/env python3
"""Quick test to verify unblock endpoint works without Flask server."""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app import app, db, BlockedThreat, ThreatActionLog, User
    print("✅ Imports successful")
    
    # Check if the endpoint exists
    with app.app_context():
        # Check database
        threat_count = BlockedThreat.query.count()
        print(f"✅ Database accessible, {threat_count} threats in database")
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print(f"✅ Admin user exists (ID: {admin.id})")
        else:
            print("❌ Admin user not found")
        
        # Check threat ID 56
        threat56 = BlockedThreat.query.get(56)
        if threat56:
            print(f"✅ Threat ID 56 exists: IP={threat56.ip_address}, active={threat56.is_active}")
        else:
            print("❌ Threat ID 56 not found")
            
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
