# Python script to replace the populate_cache_async function
import re

with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

# Define the new function
new_function = '''    def populate_cache_async():
        """Async cache population - doesn't block server startup. Only populates if cache is empty."""
        import time
        time.sleep(2)  # Give server time to start
        try:
            with app.app_context():
                # Check if cache already has data
                try:
                    with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                        existing_cache = json.load(f)
                    if len(existing_cache) > 0:
                        print(f"[CACHE] Existing cache has {len(existing_cache)} threats - preserving")
                        return  # Don't overwrite existing data
                except FileNotFoundError:
                    print("[CACHE] No cache file found - will create new one")
                except Exception:
                    print("[CACHE] Cache file exists but couldn't read - will try to populate")
                
                # Only fetch if cache is empty or missing
                import requests
                headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
                params = {"limit": 30, "modified_since": "1h"}
                try:
                    resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=5)
                    if resp.ok:
                        threats = fetch_and_cache(limit=30, modified_since="1h")
                        if threats:
                            print(f"[CACHE] Startup cache populated with {len(threats)} threats")
                    else:
                        print(f"[CACHE] OTX returned {resp.status_code}, using empty cache")
                except requests.exceptions.Timeout:
                    print("[CACHE] OTX timeout during startup - cache remains empty")
                except Exception as e:
                    print(f"[CACHE] Startup cache failed: {e}")
        except Exception as e:
            print(f"[CACHE] WARNING: Async cache population error: {e}")'''

# Find and replace the old function
pattern = r'    def populate_cache_async\(\):.*?(?=\n    # Start background updater)'
content = re.sub(pattern, new_function + '\n', content, flags=re.DOTALL)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print("✅ Updated populate_cache_async to preserve existing cache")
