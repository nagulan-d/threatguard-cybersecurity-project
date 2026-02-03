import json

# Check if cache file exists and has data
try:
    with open("recent_threats.json", "r", encoding="utf-8") as f:
        existing_cache = json.load(f)
    print(f"✅ Cache file exists with {len(existing_cache)} threats")
    if len(existing_cache) > 0:
        print("✅ Cache has data - will preserve it")
    else:
        print("⚠️ Cache is empty - needs population")
except FileNotFoundError:
    print("❌ No cache file found")
except Exception as e:
    print(f"❌ Error reading cache: {e}")
