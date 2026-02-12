from app import app, _send_threat_notifications, User, ThreatSubscription
import json

# Test 1: Auto notification system - should only send IP threats
print("=" * 70)
print("TEST 1: AUTO NOTIFICATION - ONLY IP THREATS")
print("=" * 70)

with app.app_context():
    # Create test threats: IP threat and domain threat
    test_threats = [
        {
            "id": "test-ip-1",
            "ip_address": "192.168.100.50",
            "type": "Malicious IP",
            "score": 85,
            "severity": "High",
            "summary": "IP-based threat - SHOULD BE SENT"
        },
        {
            "id": "test-domain-1",
            "indicator": "malware-domain.net",
            "type": "Malicious Domain",
            "score": 88,
            "severity": "High",
            "summary": "Domain threat - SHOULD BE SKIPPED"
        },
        {
            "id": "test-ip-2",
            "ip": "10.20.30.40",
            "type": "C2 Server",
            "score": 92,
            "severity": "Critical",
            "summary": "Another IP threat - SHOULD BE SENT"
        }
    ]
    
    print(f"\n📋 Test Threats:")
    for t in test_threats:
        ip = t.get("ip") or t.get("ip_address") or t.get("indicator") or "N/A"
        print(f"   - {t['type']}: {ip} (Score: {t['score']})")
    
    print(f"\n🚀 Calling auto notification system...")
    _send_threat_notifications(test_threats)
    
    print("\n" + "=" * 70)
    print("EXPECTED: Only 2 IP threats should be processed (domain skipped)")
    print("=" * 70)

print("\n\nTest complete! Check output above to verify:")
print("✓ Should see: '2 IP-based high-risk threats eligible'")
print("✓ Should NOT process the domain threat")
