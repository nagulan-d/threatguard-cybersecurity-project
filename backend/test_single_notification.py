#!/usr/bin/env python
"""Run manual test to verify email notifications are working."""

from app import app, _send_threat_notifications
import json

app.app_context().push()

print("=" * 60)
print("TESTING THREAT EMAIL NOTIFICATIONS")
print("=" * 60)

# Load one high-risk threat for testing
with open("recent_threats.json", "r", encoding="utf-8") as f:
    threats = json.load(f)

# Get just one high-risk threat for testing
high_risk = [t for t in threats if t.get("score", 0) >= 75][:1]

if high_risk:
    print(f"\n✅ Found {len(high_risk)} high-risk threat for testing")
    print(f"   IP: {high_risk[0].get('ip')}")
    print(f"   Score: {high_risk[0].get('score')}")
    print(f"   Type: {high_risk[0].get('type')}")
    
    print("\n📧 Sending test notification...")
    _send_threat_notifications(high_risk)
    
    print("\n" + "=" * 60)
    print("CHECK YOUR EMAIL INBOX NOW!")
    print(f"✅ Subject should be: Security Update - Network Activity Report")
    print("✅ IP should be partially masked (xxx.xxx)")  
    print("✅ No emojis in subject or body")
    print("✅ Blue header (not red)")
    print("✅ Button says 'Review and Take Action' (not 'Block This IP')")
    print("=" * 60)
else:
    print("❌ No high-risk threats found for testing")
