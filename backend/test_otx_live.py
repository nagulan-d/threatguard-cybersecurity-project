import requests
import json

API_KEY = "130bcad12caf68bd605a3fe06c0207f936dca72c7c5c9ab3f8c5f3ac9228debe"
headers = {"X-OTX-API-KEY": API_KEY}
params = {"limit": 100, "modified_since": "24h"}

print("Testing OTX API...")
resp = requests.get(
    "https://otx.alienvault.com/api/v1/indicators/export",
    headers=headers,
    params=params,
    timeout=30
)

print(f"Status: {resp.status_code}")
print(f"Content Length: {len(resp.text)}")
print(f"Content Type: {resp.headers.get('Content-Type')}")

# Try parsing as NDJSON
lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
print(f"\nTotal lines: {len(lines)}")

indicators = []
for i, line in enumerate(lines[:20]):
    try:
        data = json.loads(line)
        indicator = data.get("indicator", "N/A")
        ind_type = data.get("type", "N/A")
        indicators.append(indicator)
        print(f"{i+1}. {ind_type}: {indicator}")
    except Exception as e:
        print(f"{i+1}. Parse error: {e}")

print(f"\n✅ Successfully parsed {len(indicators)} indicators")
