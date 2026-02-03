#!/usr/bin/env python3
"""
Test the deactivate endpoint with actual admin token to capture the real error.
"""

import requests
import json

API_URL = "http://127.0.0.1:5000/api"

print("=" * 70)
print("TEST: Deactivate Endpoint with Valid Admin Token")
print("=" * 70)

# Step 1: Login as admin
print("\n[1/2] Logging in as admin...")
login_response = requests.post(f"{API_URL}/login", json={
    "username": "admin",
    "password": "password"
})

if login_response.status_code != 200:
    print(f"❌ Login failed: {login_response.status_code}")
    print(f"Response: {login_response.text}")
    exit(1)

login_data = login_response.json()
token = login_data.get("token")
print(f"✅ Login successful! Token: {token[:30]}...")

# Step 2: Try to deactivate IP with token
print("\n[2/2] Testing deactivate endpoint with token for threat_id=50...")
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

try:
    deactivate_response = requests.post(
        f"{API_URL}/unblock-threat/50",
        headers=headers,
        json={},
        timeout=5
    )
    
    print(f"\nStatus Code: {deactivate_response.status_code}")
    print(f"Response Text: {deactivate_response.text}")
    
    if deactivate_response.status_code >= 400:
        print(f"\n⚠️  Error detected!")
        try:
            error_data = deactivate_response.json()
            print(f"Error response: {json.dumps(error_data, indent=2)}")
        except:
            print(f"Raw response: {deactivate_response.text}")
    else:
        print(f"\n✅ Success!")
        data = deactivate_response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
except Exception as e:
    print(f"❌ Exception occurred: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
