import requests
import json
import random

API_KEY = "130bcad12caf68bd605a3fe06c0207f936dca72c7c5c9ab3f8c5f3ac9228debe"
headers = {"X-OTX-API-KEY": API_KEY}

# Fetch pulses
from datetime import datetime, timedelta
since = (datetime.utcnow() - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S")

resp = requests.get(
    "https://otx.alienvault.com/api/v1/pulses/subscribed",
    headers=headers,
    params={"limit": 20, "modified_since": since},
    timeout=30
)

print(f"Response Status: {resp.status_code}\n")

data = resp.json()
pulses = data.get("results", [])
print(f"Found {len(pulses)} pulses\n")

# Extract all indicators
all_indicators = []
for pulse in pulses:
    indicators = pulse.get("indicators", [])
    all_indicators.extend(indicators)

print(f"Total indicators: {len(all_indicators)}\n")

# Show first 20
print("First 20 indicators:")
for i, ind in enumerate(all_indicators[:20]):
    print(f"{i+1}. {ind.get('type')}: {ind.get('indicator')}")

print(f"\n=== Testing randomization ===")
# Shuffle and take 5, three times
for attempt in range(3):
    test_list = list(all_indicators)  # Make a copy
    random.shuffle(test_list)
    print(f"\nAttempt {attempt+1}:")
    for ind in test_list[:5]:
        print(f"  - {ind.get('indicator')}")
