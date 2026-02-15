"""
Quick test script to verify the real-time threat fetcher works correctly.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Verify required environment variables
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    print("❌ ERROR: API_KEY not found in .env file")
    print("   Please add your AlienVault OTX API key to .env:")
    print("   API_KEY=your_otx_api_key_here")
    sys.exit(1)

print("✅ Environment variables loaded successfully")
print(f"   API_KEY: {API_KEY[:10]}...{API_KEY[-4:]}")

# Import and run the fetcher
try:
    from fetch_realtime_threats import fetch_and_store_threats
    
    print("\n" + "="*60)
    print("🧪 TESTING REAL-TIME THREAT FETCHER")
    print("="*60)
    
    # Test with small limit first
    fetch_and_store_threats(limit=10, modified_since="24h")
    
    print("\n✅ Test completed successfully!")
    print("\nYou can now run the full fetcher with:")
    print("   python fetch_realtime_threats.py --limit 50 --modified_since 24h")
    print("   python fetch_realtime_threats.py --continuous --interval 300")
    
except Exception as e:
    print(f"\n❌ ERROR during test: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
