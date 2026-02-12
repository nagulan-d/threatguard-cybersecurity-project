#!/usr/bin/env python
"""Test sending notifications with cached threats."""

from app import app, _send_threat_notifications
from datetime import datetime
import json

app.app_context().push()

print(f"[{datetime.now().strftime('%H:%M:%S')}] Loading cached threats...")

# Load threats from cache
with open("recent_threats.json", "r", encoding="utf-8") as f:
    threats = json.load(f)

print(f"[{datetime.now().strftime('%H:%M:%S')}] Loaded {len(threats)} threats")

# Filter for high-risk threats (>=75)
high_risk = [t for t in threats if t.get("score", 0) >= 75]
print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(high_risk)} high-risk threats (score >= 75)")

if high_risk:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending notifications...")
    _send_threat_notifications(threats)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Done!")
else:
    print("No high-risk threats to notify about")
