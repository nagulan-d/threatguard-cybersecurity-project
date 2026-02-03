import requests
import json

API_KEY = "130bcad12caf68bd605a3fe06c0207f936dca72c7c5c9ab3f8c5f3ac9228debe"
headers = {"X-OTX-API-KEY": API_KEY}

print("=== Testing Export API ===")
resp = requests.get(
    "https://otx.alienvault.com/api/v1/indicators/export",
    headers=headers,
    params={"limit": 50, "modified_since": "24h"},
    timeout=30
)
print(f"Export API Status: {resp.status_code}")
print(f"Response: {resp.text[:500]}")

print("\n=== Testing Pulses API (subscribed) ===")
resp2 = requests.get(
    "https://otx.alienvault.com/api/v1/pulses/subscribed",
    headers=headers,
    params={"limit": 10, "modified_since": "2025-01-26T00:00:00"},
    timeout=30
)
print(f"Pulses API Status: {resp2.status_code}")
if resp2.status_code == 200:
    data = resp2.json()
    results = data.get("results", [])
    print(f"Pulses found: {len(results)}")
    for i, pulse in enumerate(results[:3]):
        print(f"\nPulse {i+1}: {pulse.get('name')}")
        indicators = pulse.get("indicators", [])
        print(f"  Indicators: {len(indicators)}")
        for ind in indicators[:5]:
            print(f"    - {ind.get('type')}: {ind.get('indicator')}")
