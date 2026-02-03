#!/usr/bin/env python
"""Fetch threats with timeout and send notifications."""

import sys
import signal
from app import app, db
from datetime import datetime
import json

# Setup timeout handler
def timeout_handler(signum, frame):
    print("[TIMEOUT] Request timed out after 60 seconds")
    sys.exit(1)

app.app_context().push()

# Set a 60-second timeout for the whole operation
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(60)

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
    signal.alarm(0)  # Cancel the alarm
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Done")
