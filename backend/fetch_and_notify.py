#!/usr/bin/env python
"""Fetch threats and send notifications."""

import sys
from app import app, db
from datetime import datetime
import json

app.app_context().push()

try:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting threat fetch...")
    from app import fetch_and_cache, _send_threat_notifications
    
    threats = fetch_and_cache(limit=20)  # Smaller limit for faster fetch
    
    if threats:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Fetched {len(threats)} threats")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending notifications...")
        
        _send_threat_notifications(threats)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Notifications complete!")
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] No threats fetched")

except KeyboardInterrupt:
    print("\n[INTERRUPTED] User interrupted")
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
finally:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Done")

