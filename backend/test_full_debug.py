#!/usr/bin/env python
"""Test notification with full debug output."""

from app import app, _send_threat_notifications, ThreatSubscription, User
import json

app.app_context().push()

print("=" * 60)
print("DEBUGGING THREAT NOTIFICATIONS")
print("=" * 60)

# Get subscriptions
subs = ThreatSubscription.query.filter_by(is_active=True).all()
print(f"\n✅ Found {len(subs)} active subscriptions:")
for sub in subs:
    user = User.query.get(sub.user_id)
    print(f"   - User: {user.username}, Email: {sub.email}, Min Score: {sub.min_risk_score}")

# Load threats
with open("recent_threats.json", "r", encoding="utf-8") as f:
    threats = json.load(f)

# Create test threats with and without IPs
test_threats = []

# Test 1: IP-based threat
ip_threat = next((t for t in threats if t.get("ip") and t.get("score", 0) >= 75), None)
if ip_threat:
    test_threats.append(ip_threat)
    print(f"\n📌 Test IP Threat: {ip_threat.get('ip')}, Score: {ip_threat.get('score')}")

# Test 2: Domain threat (no IP)
domain_threat = next((t for t in threats if 't' not in (t.get("ip") or "") and t.get("score", 0) >= 75), None)
if domain_threat:
    test_threats.append(domain_threat)
    print(f"📌 Test Domain Threat: {domain_threat.get('type')}, Score: {domain_threat.get('score')}")

if test_threats:
    print(f"\n🚀 Sending notifications for {len(test_threats)} threats...\n")
    _send_threat_notifications(test_threats)
    print("\n✅ Check your email!")
else:
    print("\n❌ No suitable threats found for testing")
