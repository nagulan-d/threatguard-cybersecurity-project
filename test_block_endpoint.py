#!/usr/bin/env python3
"""
Test the block-threat endpoint with proper error handling
"""
import requests
import json

BASE_URL = "http://localhost:5000"

def test_block_endpoint():
    print("\n" + "="*60)
    print("TESTING BLOCK-THREAT ENDPOINT")
    print("="*60)
    
    # Step 1: Login as admin
    print("\n[1] Logging in as admin...")
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    
    login_resp = requests.post(f"{BASE_URL}/api/login", json=login_data)
    if login_resp.status_code != 200:
        print(f"❌ Login failed: {login_resp.json()}")
        return False
    
    login_result = login_resp.json()
    auth_token = login_result.get("token")
    print(f"✅ Login successful, token: {auth_token[:30]}...")
    
    # Step 2: Block a threat via dashboard (without token)
    print("\n[2] Testing block via dashboard (no token)...")
    block_data = {
        "ip_address": "192.168.1.50",
        "threat_type": "Malware",
        "risk_category": "High",
        "risk_score": 85.0,
        "summary": "Test malware threat",
        "reason": "Testing dashboard block without token"
    }
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    print(f"Request JSON: {json.dumps(block_data, indent=2)}")
    
    block_resp = requests.post(
        f"{BASE_URL}/api/block-threat",
        json=block_data,
        headers=headers
    )
    
    print(f"Response Status: {block_resp.status_code}")
    print(f"Response Headers: {dict(block_resp.headers)}")
    print(f"Response Body: {block_resp.text[:500]}")
    
    try:
        response_json = block_resp.json()
        print(f"Response JSON: {json.dumps(response_json, indent=2)}")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {e}")
        return False
    
    if block_resp.status_code == 201:
        print("✅ Dashboard block successful!")
        return True
    else:
        print(f"❌ Dashboard block failed with status {block_resp.status_code}")
        return False

if __name__ == "__main__":
    try:
        test_block_endpoint()
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
