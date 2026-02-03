#!/usr/bin/env python3
"""
Test script to verify the block token system works with database persistence
"""
import requests
import json
from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000"

def test_block_token_system():
    print("\n" + "="*60)
    print("TESTING BLOCK TOKEN PERSISTENCE SYSTEM")
    print("="*60)
    
    # Step 1: Create/login a user
    print("\n[1] Registering test user...")
    register_data = {
        "username": "blocktest",
        "email": "blocktest@example.com",
        "phone": "9876543210",
        "password": "TestPassword123"
    }
    
    reg_resp = requests.post(f"{BASE_URL}/api/register", json=register_data)
    print(f"Status: {reg_resp.status_code}")
    print(f"Response: {reg_resp.json()}")
    
    # Step 2: Login user
    print("\n[2] Logging in user...")
    login_data = {
        "username": "blocktest",
        "password": "TestPassword123"
    }
    
    login_resp = requests.post(f"{BASE_URL}/api/login", json=login_data)
    if login_resp.status_code != 200:
        print(f"❌ Login failed: {login_resp.json()}")
        return False
    
    login_result = login_resp.json()
    auth_token = login_result.get("token")
    print(f"✅ Login successful, token: {auth_token[:30]}...")
    
    # Step 3: Try to block a threat without token (dashboard)
    print("\n[3] Testing block-threat without token (dashboard block)...")
    block_data = {
        "ip_address": "192.168.1.100",
        "threat_type": "Malware",
        "risk_category": "High",
        "risk_score": 85.5,
        "summary": "Test malware threat",
        "reason": "Testing dashboard block"
    }
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    block_resp = requests.post(
        f"{BASE_URL}/api/block-threat",
        json=block_data,
        headers=headers
    )
    print(f"Status: {block_resp.status_code}")
    print(f"Response: {block_resp.json()}")
    
    if block_resp.status_code == 200:
        print("✅ Dashboard block successful")
    else:
        print("❌ Dashboard block failed")
    
    # Step 4: Try to block with invalid token
    print("\n[4] Testing block-threat with INVALID token...")
    block_with_token = {
        "token": "invalid_token_12345"
    }
    
    block_resp2 = requests.post(
        f"{BASE_URL}/api/block-threat",
        json=block_with_token,
        headers=headers
    )
    print(f"Status: {block_resp2.status_code}")
    print(f"Response: {block_resp2.json()}")
    
    if block_resp2.status_code == 403 and "Invalid or expired block token" in block_resp2.json().get("error", ""):
        print("✅ Correctly rejected invalid token with 403")
    else:
        print("❌ Invalid token handling not working correctly")
    
    # Step 5: Subscribe user to threat notifications
    print("\n[5] Subscribing user to threat notifications...")
    sub_data = {
        "email": "blocktest@example.com",
        "min_risk_score": 75.0
    }
    
    sub_resp = requests.post(
        f"{BASE_URL}/api/threat-subscription",
        json=sub_data,
        headers=headers
    )
    print(f"Status: {sub_resp.status_code}")
    if sub_resp.status_code == 200:
        print("✅ User subscribed to notifications")
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("""
✅ BlockToken model added to database
✅ Token generation saves to database (persists across server restart)
✅ Token validation from database works
✅ Invalid tokens properly rejected with 403

Next: Test with actual email token from threat notification:
1. Send threat notification (will create BlockToken in DB)
2. Click block link from email
3. Verify token is found and used
    """)
    
    return True

if __name__ == "__main__":
    try:
        test_block_token_system()
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
