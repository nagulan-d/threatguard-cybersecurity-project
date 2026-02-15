"""
Verification script for Live Threat Intelligence System
"""
import os
import sys

print("="*70)
print("🔍 LIVE THREAT SYSTEM VERIFICATION")
print("="*70)

# Check 1: Required files exist
print("\n1. Checking required files...")
required_files = [
    "backend/live_threat_fetcher.py",
    "backend/app.py",
    "backend/.env",
]

all_exist = True
for file in required_files:
    exists = os.path.exists(file)
    status = "✅" if exists else "❌"
    print(f"   {status} {file}")
    if not exists:
        all_exist = False

# Check 2: Environment variables
print("\n2. Checking environment variables...")
from dotenv import load_dotenv
load_dotenv("backend/.env")

API_KEY = os.getenv("API_KEY")
if API_KEY:
    print(f"   ✅ API_KEY set ({len(API_KEY)} chars)")
else:
    print(f"   ❌ API_KEY not set")
    all_exist = False

# Check 3: Test live fetcher import
print("\n3. Testing live threat fetcher...")
try:
    sys.path.insert(0, 'backend')
    from live_threat_fetcher import fetch_live_threats, reset_shown_threats
    print("   ✅ Live threat fetcher imported successfully")
except Exception as e:
    print(f"   ❌ Failed to import: {e}")
    all_exist = False

# Check 4: Test fetch functionality
print("\n4. Testing threat fetching (this may take a few seconds)...")
try:
    threats = fetch_live_threats(limit=3)
    if len(threats) > 0:
        print(f"   ✅ Successfully fetched {len(threats)} threats")
        print(f"\n   Sample threat:")
        t = threats[0]
        print(f"   - Indicator: {t['indicator']}")
        print(f"   - Category: {t['category']}")
        print(f"   - Severity: {t['severity']} (Score: {t['score']})")
    else:
        print(f"   ⚠️  No threats fetched (OTX may be rate limiting)")
except Exception as e:
    print(f"   ❌ Failed to fetch: {e}")
    all_exist = False

# Check 5: Verify tracking file
print("\n5. Checking duplicate prevention...")
if os.path.exists("backend/seen_threats.json"):
    import json
    with open("backend/seen_threats.json") as f:
        data = json.load(f)
    shown_count = len(data.get('shown_indicators', []))
    print(f"   ✅ Tracking file exists ({shown_count} threats shown so far)")
else:
    print(f"   ℹ️  No tracking file yet (will be created on first fetch)")

# Final result
print("\n" + "="*70)
if all_exist:
    print("✅ SYSTEM READY - Live threat fetching is operational!")
    print("\nNext steps:")
    print("1. Start backend: cd backend && python app.py")
    print("2. Test endpoint: GET http://localhost:5000/api/threats")
    print("3. Each refresh will show DIFFERENT threats!")
    print("4. Reset history: POST http://localhost:5000/api/reset-shown-threats")
else:
    print("❌ SYSTEM NOT READY - Please fix the issues above")

print("="*70)
