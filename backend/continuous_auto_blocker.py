"""
Continuous Auto-Blocking Service
Monitors threats API and automatically blocks high-severity threats
Runs continuously in the background
"""
import time
import sys
import os
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auto_block_high_threats import auto_block_high_threats, load_blocked_ips
from dotenv import load_dotenv

load_dotenv()

# Configuration
CHECK_INTERVAL = int(os.getenv("AUTO_BLOCK_CHECK_INTERVAL", 60))  # Check every 60 seconds
MAX_BLOCKS_PER_CYCLE = int(os.getenv("AUTO_BLOCK_MAX_PER_CYCLE", 10))

def main():
    """Run continuous auto-blocking service."""
    print("\n" + "="*70)
    print("🛡️  CONTINUOUS AUTO-BLOCKING SERVICE")
    print("="*70)
    print(f"⏱️  Check interval: {CHECK_INTERVAL} seconds")
    print(f"🎯 Max blocks per cycle: {MAX_BLOCKS_PER_CYCLE}")
    print("="*70)
    print("\n⚠️  Press Ctrl+C to stop\n")
    
    cycle = 1
    
    try:
        while True:
            print(f"\n{'─'*70}")
            print(f"🔄 CYCLE {cycle} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'─'*70}")
            
            # Load current blocked IPs count
            blocked_ips = load_blocked_ips()
            print(f"📊 Currently tracking: {len(blocked_ips)} blocked IPs\n")
            
            # Run auto-blocking
            try:
                auto_block_high_threats()
            except Exception as e:
                print(f"❌ Error in auto-blocking: {e}\n")
            
            # Wait before next check
            print(f"\n⏸️  Sleeping for {CHECK_INTERVAL} seconds...")
            print(f"{'─'*70}\n")
            
            time.sleep(CHECK_INTERVAL)
            cycle += 1
            
    except KeyboardInterrupt:
        print("\n\n⛔ Stopping continuous auto-blocking service...")
        print(f"✅ Completed {cycle - 1} cycles")
        print("\n" + "="*70)
        blocked_ips = load_blocked_ips()
        print(f"📊 FINAL STATS")
        print("="*70)
        print(f"Total IPs blocked: {len(blocked_ips)}")
        print(f"Total cycles run: {cycle - 1}")
        print("="*70 + "\n")

if __name__ == "__main__":
    main()
