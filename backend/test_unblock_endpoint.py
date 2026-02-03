#!/usr/bin/env python3
"""Test unblock endpoint with actual HTTP requests."""

import sys
import os
import time
import threading
import requests
import json

sys.path.insert(0, os.path.dirname(__file__))

from app import app

def run_flask():
    """Run Flask in background thread."""
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

# Start Flask in background
print("[START] Starting Flask server...")
flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()

# Wait for server to start
time.sleep(3)

try:
    # Test 1: Login
    print("\n[TEST 1] Login as admin...")
    login_res = requests.post('http://127.0.0.1:5000/api/login', 
        json={'username': 'admin', 'password': 'admin123'},
        timeout=5)
    print(f"Status: {login_res.status_code}")
    if login_res.status_code == 200:
        token = login_res.json()['token']
        print(f"[OK] Token received: {token[:30]}...")
        
        # Test 2: Unblock threat
        print("\n[TEST 2] Unblock threat ID 56...")
        headers = {'Authorization': f'Bearer {token}'}
        unblock_res = requests.post('http://127.0.0.1:5000/api/unblock-threat/56', 
            headers=headers,
            json={},
            timeout=5)
        print(f"Status: {unblock_res.status_code}")
        print(f"Response: {json.dumps(unblock_res.json(), indent=2)}")
        
        if unblock_res.status_code == 200:
            print("[OK] UNBLOCK SUCCESSFUL!")
        else:
            print(f"[ERROR] Unblock failed with status {unblock_res.status_code}")
    else:
        print(f"[ERROR] Login failed: {login_res.text}")
        
except Exception as e:
    print(f"[ERROR] Error: {e}")
    import traceback
    traceback.print_exc()

print("\n[DONE] Tests complete!")
sys.exit(0)
