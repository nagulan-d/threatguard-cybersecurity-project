"""
Test manual notification endpoint with threats that have NO IP address.
This should now work without errors.
"""
from app import app, db, User
import json

with app.app_context():
    print("=" * 70)
    print("TEST: MANUAL NOTIFICATION WITHOUT IP")
    print("=" * 70)
    
    # Get admin user
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        print("❌ No admin user found")
        exit(1)
    
    # Get target user
    target_user = User.query.filter_by(username='kannan').first()
    if not target_user:
        print("❌ No target user found")
        exit(1)
    
    print(f"\n✓ Admin: {admin.username}")
    print(f"✓ Target: {target_user.username} ({target_user.email})")
    
    # DOMAIN THREAT (NO IP)
    domain_threat = {
        "type": "Phishing Domain",
        "indicator": "evil-phishing-site.com",
        "score": 82,
        "severity": "High",
        "summary": "Phishing domain detected - no IP address available",
        "timestamp": "2026-02-12T10:30:00"
    }
    
    # URL THREAT (NO IP)
    url_threat = {
        "type": "Malicious URL",
        "indicator": "http://malware-download.net/payload.exe",
        "score": 95,
        "severity": "Critical",
        "summary": "Malware distribution URL - no IP address",
        "timestamp": "2026-02-12T11:45:00"
    }
    
    print("\n📧 Test Threats (NO IP ADDRESS):")
    print(f"   1. {domain_threat['type']}: {domain_threat['indicator']}")
    print(f"   2. {url_threat['type']}: {url_threat['indicator']}")
    
    print("\n" + "=" * 70)
    print("To test manually, use these curl commands:")
    print("=" * 70)
    
    print("\nFirst, login to get token:")
    print(f'curl -X POST http://localhost:5000/api/login \\')
    print(f'  -H "Content-Type: application/json" \\')
    print(f'  -d \'{{"username": "{admin.username}", "password": "admin123"}}\'')
    
    print("\n\nThen send notification (replace <TOKEN> with actual token):")
    print('curl -X POST http://localhost:5000/api/send-notification \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -H "Authorization: Bearer <TOKEN>" \\')
    print(f'  -d \'{{"threat": {json.dumps(domain_threat)}, "user_email": "{target_user.email}"}}\'')
    
    print("\n" + "=" * 70)
    print("EXPECTED RESULT:")
    print("✓ Should return success (not 400 error)")
    print("✓ Email should be sent without block button")
    print("✓ No 'Valid IP address required' error")
    print("=" * 70)
