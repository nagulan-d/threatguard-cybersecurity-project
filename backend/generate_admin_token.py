"""Generate JWT token for admin user"""
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")

# Create token with long expiration (30 days)
payload = {
    "user_id": 1,  # Assuming admin user ID is 1
    "role": "admin",
    "exp": datetime.utcnow() + timedelta(days=30)
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

print("=" * 60)
print("Admin JWT Token Generated")
print("=" * 60)
print(f"\nToken: {token}\n")
print("This token will expire in 30 days")
print("\nTo use with auto-block monitor:")
print(f"  1. Copy the token above")
print(f"  2. Save it to: .auto_blocker_token")
print(f"  3. Or add to agent_config.json in vm_agent folder")
print("=" * 60)

# Save to token file
try:
    with open('.auto_blocker_token', 'w') as f:
        f.write(token)
    print("\n[OK] Token saved to .auto_blocker_token")
except Exception as e:
    print(f"\n[ERROR] Failed to save token: {e}")
