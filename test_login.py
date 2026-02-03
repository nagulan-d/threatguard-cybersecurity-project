"""
Quick Login Test Script
This script tests the login endpoint and returns a valid token
"""

import requests
import json

# Backend URL
API_URL = "http://127.0.0.1:5000/api"

def test_login(username, password):
    """Test login and get token"""
    try:
        print(f"🔐 Attempting login for user: {username}")
        response = requests.post(
            f"{API_URL}/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            role = data.get('role')
            print(f"✅ Login successful!")
            print(f"👤 Role: {role}")
            print(f"🔑 Token: {token[:50]}...")
            print(f"\n📋 Full token (copy this):\n{token}\n")
            return token, role
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"Error: {response.json()}")
            return None, None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None

def test_api_with_token(token):
    """Test /api/me endpoint with token"""
    try:
        print(f"\n🧪 Testing /api/me endpoint...")
        response = requests.get(
            f"{API_URL}/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API test successful!")
            print(f"User info: {json.dumps(data, indent=2)}")
            return True
        else:
            print(f"❌ API test failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 70)
    print("ThreatGuard - Login Test Script")
    print("=" * 70)
    print()
    
    # Test with default admin credentials
    print("Testing with default admin credentials:")
    print("Username: admin")
    print("Password: admin123")
    print()
    
    token, role = test_login("admin", "admin123")
    
    if token:
        # Test the token
        test_api_with_token(token)
        
        print("\n" + "=" * 70)
        print("✅ LOGIN SUCCESSFUL!")
        print("=" * 70)
        print()
        print("📌 NEXT STEPS:")
        print("1. Open http://localhost:3000 in your browser")
        print("2. Click 'Login' or navigate to /login")
        print("3. Enter:")
        print("   Username: admin")
        print("   Password: admin123")
        print("4. You should be redirected to the dashboard")
        print()
        print("💡 TIP: If you see 401 errors, make sure you:")
        print("   - Actually logged in through the frontend")
        print("   - The token is stored in localStorage")
        print("   - You're not accessing /dashboard directly without logging in")
        print()
    else:
        print("\n" + "=" * 70)
        print("❌ LOGIN FAILED!")
        print("=" * 70)
        print()
        print("🔧 TROUBLESHOOTING:")
        print("1. Make sure the backend server is running")
        print("2. Check if you have an admin user in the database")
        print("3. Try creating an admin user with:")
        print("   python backend/create_admin.py")
        print()
