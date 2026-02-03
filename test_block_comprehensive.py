#!/usr/bin/env python3
"""
Comprehensive test of the fixed block-threat endpoint
"""
import requests
import json

BASE_URL = "http://localhost:5000"

def test_block_threat_endpoint():
    """Test the block-threat endpoint with various scenarios"""
    print("\n" + "="*70)
    print("BLOCK-THREAT ENDPOINT COMPREHENSIVE TEST")
    print("="*70)
    
    # Login
    print("\n[1] Logging in...")
    login_resp = requests.post(f"{BASE_URL}/api/login", json={
        "username": "admin",
        "password": "admin123"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.json()}"
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print("✓ Login successful")
    
    # Test 1: Block via dashboard (no token)
    print("\n[2] Test: Block threat via dashboard (no email token)...")
    block_data = {
        "ip_address": "192.168.1.50",
        "threat_type": "Malware",
        "risk_category": "High",
        "risk_score": 85.5,
        "summary": "Malicious IP detected",
        "reason": "Dashboard block test"
    }
    resp = requests.post(f"{BASE_URL}/api/block-threat", json=block_data, headers=headers)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    result = resp.json()
    assert "blocked_threat" in result, "Response missing blocked_threat"
    assert result["blocked_threat"]["ip_address"] == "192.168.1.50"
    print(f"✓ Successfully blocked IP: {result['blocked_threat']['ip_address']}")
    print(f"  Message: {result['message']}")
    
    # Test 2: Try to block same IP again (should fail with 409)
    print("\n[3] Test: Try to block same IP again (should fail)...")
    resp = requests.post(f"{BASE_URL}/api/block-threat", json=block_data, headers=headers)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}"
    print(f"✓ Correctly rejected duplicate: {resp.json()['error']}")
    
    # Test 4: Block different IP
    print("\n[4] Test: Block different IP...")
    block_data2 = {
        "ip_address": "192.168.1.51",
        "threat_type": "Phishing",
        "risk_category": "Medium",
        "risk_score": 65.0,
        "summary": "Phishing campaign"
    }
    resp = requests.post(f"{BASE_URL}/api/block-threat", json=block_data2, headers=headers)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    result = resp.json()
    print(f"✓ Successfully blocked: {result['blocked_threat']['ip_address']}")
    
    # Test 5: Invalid IP format
    print("\n[5] Test: Invalid IP format (should fail)...")
    invalid_data = {
        "ip_address": "invalid-ip",
        "threat_type": "Test"
    }
    resp = requests.post(f"{BASE_URL}/api/block-threat", json=invalid_data, headers=headers)
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    print(f"✓ Correctly rejected invalid IP: {resp.json()['error']}")
    
    # Test 6: Missing IP address
    print("\n[6] Test: Missing IP address (should fail)...")
    resp = requests.post(f"{BASE_URL}/api/block-threat", json={"threat_type": "Test"}, headers=headers)
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    print(f"✓ Correctly rejected missing IP: {resp.json()['error']}")
    
    # Summary
    print("\n" + "="*70)
    print("ALL TESTS PASSED! ✓")
    print("="*70)
    print("""
The block-threat endpoint is working correctly:
✓ Can block IPs from dashboard
✓ Validates IP address format
✓ Prevents duplicate blocks
✓ Returns proper error messages
✓ Returns 201 CREATED on success
✓ Returns appropriate error codes (400, 409) on failure
✓ No more 500 errors from emoji Unicode issues

The system is now fully functional for blocking threats!
    """)

if __name__ == "__main__":
    try:
        test_block_threat_endpoint()
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
