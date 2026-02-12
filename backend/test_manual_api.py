"""
Automated test for manual notification endpoint without IP address.
"""
from app import app, db, User
import json

with app.app_context():
    print("=" * 70)
    print("AUTOMATED TEST: Manual Notification API without IP")
    print("=" * 70)
    
    # Get admin user
    admin = User.query.filter_by(role='admin').first()
    target = User.query.filter_by(username='kannan').first()
    
    if not admin or not target:
        print("❌ Required users not found")
        exit(1)
    
    # Create test client
    client = app.test_client()
    
    # Login
    print("\n1️⃣ Logging in as admin...")
    login_response = client.post('/api/login',
        json={'username': admin.username, 'password': 'admin123'},
        content_type='application/json'
    )
    
    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.status_code}")
        print(login_response.get_json())
        exit(1)
    
    token = login_response.get_json().get('token')
    print(f"✓ Login successful, got token")
    
    # Test 1: Domain threat (NO IP)
    print("\n2️⃣ Sending notification for DOMAIN threat (no IP)...")
    domain_threat = {
        "type": "Phishing Domain",
        "indicator": "evil-phishing-site.com",
        "score": 82,
        "severity": "High",
        "summary": "Phishing domain detected - no IP address available",
        "timestamp": "2026-02-12T10:30:00"
    }
    
    response1 = client.post('/api/send-notification',
        json={'threat': domain_threat, 'user_email': target.email},
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )
    
    print(f"   Status: {response1.status_code}")
    print(f"   Response: {response1.get_json()}")
    
    if response1.status_code == 200:
        print("   ✅ SUCCESS - Domain threat notification sent!")
    else:
        print("   ❌ FAILED - Should have succeeded without IP")
    
    # Test 2: URL threat (NO IP)
    print("\n3️⃣ Sending notification for URL threat (no IP)...")
    url_threat = {
        "type": "Malicious URL",
        "indicator": "http://malware-download.net/payload.exe",
        "score": 95,
        "severity": "Critical",
        "summary": "Malware distribution URL - no IP address"
    }
    
    response2 = client.post('/api/send-notification',
        json={'threat': url_threat, 'user_email': target.email},
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )
    
    print(f"   Status: {response2.status_code}")
    print(f"   Response: {response2.get_json()}")
    
    if response2.status_code == 200:
        print("   ✅ SUCCESS - URL threat notification sent!")
    else:
        print("   ❌ FAILED - Should have succeeded without IP")
    
    # Test 3: IP threat (WITH IP) - should still work
    print("\n4️⃣ Sending notification for IP threat (with IP)...")
    ip_threat = {
        "type": "C2 Server",
        "ip_address": "192.168.50.100",
        "score": 90,
        "severity": "High",
        "summary": "Command & Control server detected"
    }
    
    response3 = client.post('/api/send-notification',
        json={'threat': ip_threat, 'user_email': target.email},
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )
    
    print(f"   Status: {response3.status_code}")
    print(f"   Response: {response3.get_json()}")
    
    if response3.status_code == 200:
        print("   ✅ SUCCESS - IP threat notification sent!")
    else:
        print("   ❌ FAILED")
    
    print("\n" + "=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"Domain threat (no IP): {'✅ PASS' if response1.status_code == 200 else '❌ FAIL'}")
    print(f"URL threat (no IP):    {'✅ PASS' if response2.status_code == 200 else '❌ FAIL'}")
    print(f"IP threat (with IP):   {'✅ PASS' if response3.status_code == 200 else '❌ FAIL'}")
    print("=" * 70)
    
    if all(r.status_code == 200 for r in [response1, response2, response3]):
        print("\n🎉 ALL TESTS PASSED! Manual notifications work with and without IP!")
    else:
        print("\n⚠️ Some tests failed. Check output above.")
