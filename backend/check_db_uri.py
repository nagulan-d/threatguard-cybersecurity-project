#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

print(f"DATABASE_URL env: {os.getenv('DATABASE_URL', 'NOT SET')}")

from app import app
print(f"Configured URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
