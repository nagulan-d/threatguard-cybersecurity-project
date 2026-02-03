#!/usr/bin/env python
"""
Simple startup script for ThreatGuard Backend with IP Blocking
Sets proper environment variables and starts the Flask app
"""

import os
import sys
import subprocess

# Set UTF-8 encoding for terminal
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Add backend directory to path
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_dir)

print("=" * 60)
print("🚀 ThreatGuard Backend Server Starting")
print("=" * 60)
print("🔒 IP Blocking: ENABLED")
print("📝 Module: ip_blocker.py")
print("=" * 60)
print()

try:
    # Change to backend directory
    os.chdir(backend_dir)
    
    # Import and run app
    from app import app
    
    print("✅ All imports successful")
    print()
    print("Starting Flask server...")
    print()
    
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )
    
except Exception as e:
    print(f"❌ Error starting server: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
