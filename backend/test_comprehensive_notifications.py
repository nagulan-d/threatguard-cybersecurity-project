#!/usr/bin/env python
"""Test notification system with different user types and threat types."""

from app import app, _send_threat_notifications, ThreatSubscription, User, db
import json

app.app_context().push()

print("=" * 70)
print("COMPREHENSIVE NOTIFICATION TEST")
print("=" * 70)

# Check user premium status
subs = ThreatSubscription.query.filter_by(is_active=True).all()
print(f"\n📋 Active Subscriptions: {len(subs)}")
for sub in subs:
    user = User.query.get(sub.user_id)
    premium_status = "PREMIUM ⭐" if (hasattr(user, 'subscription') and user.subscription == "premium") else "FREE"
    print(f"   - {user.username} ({sub.email}) - {premium_status}")

# Load threats
with open("recent_threats.json", "r", encoding="utf-8") as f:
    threats = json.load(f)

# Find test threats
ip_threat = next((t for t in threats if t.get("ip") and t.get("score", 0) >= 75), None)
domain_threat = next((t for t in threats if not t.get("ip") and t.get("score", 0) >= 75), None)

test_threats = []
if ip_threat:
    test_threats.append(ip_threat)
    print(f"\n✅ IP Threat: {ip_threat.get('ip')}, Score: {ip_threat.get('score')}")
    
if domain_threat:
    test_threats.append(domain_threat)
    print(f"✅ Domain Threat: {domain_threat.get('type')}, Score: {domain_threat.get('score')}")

if not test_threats:
    print("\n❌ No suitable threats found")
    exit()

print(f"\n{'='*70}")
print(f"🚀 SENDING NOTIFICATIONS FOR {len(test_threats)} THREATS...")
print(f"{'='*70}\n")

_send_threat_notifications(test_threats)

print(f"\n{'='*70}")
print("EXPECTED RESULTS:")
print("="*70)
print("✅ Premium users with IP threats: Should get 'Block This Threat' button")
print("✅ Free users with IP threats: Should get notification only (no block button)")
print("✅ All users with domain threats: Should get notification only (no IP to block)")
print("="*70)
print("\n📧 Check your email inbox now!")
