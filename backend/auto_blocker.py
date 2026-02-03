"""
Auto-Blocking Agent for ThreatGuard
Automatically blocks high-risk threats at the OS firewall level
Runs as a Windows Service using NSSM
"""

import requests
import json
import time
import logging
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

BACKEND_URL = "http://localhost:5000"
RISK_THRESHOLD = 75  # Block IPs with score >= 75 (High risk)
CHECK_INTERVAL = 300  # Check every 5 minutes (300 seconds)
MAX_BLOCKS_PER_DAY = 10  # Maximum blocks per day (5-10 range)
MIN_BLOCKS_PER_DAY = 5   # Minimum target blocks per day
JWT_TOKEN = None  # Will be set from token file or admin

# Logging configuration
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "auto_blocker.log"

# Token file (store JWT in secure location)
TOKEN_FILE = Path(__file__).parent / ".auto_blocker_token"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_token():
    """Load JWT token from file"""
    try:
        if TOKEN_FILE.exists():
            with open(TOKEN_FILE, 'r') as f:
                token = f.read().strip()
                if token:
                    logger.info("Loaded JWT token from file")
                    return token
    except Exception as e:
        logger.error(f"Failed to load token: {e}")
    return None

def save_token(token):
    """Save JWT token to file"""
    try:
        with open(TOKEN_FILE, 'w') as f:
            f.write(token)
        # Restrict file permissions (Windows)
        import os
        os.chmod(TOKEN_FILE, 0o600)
        logger.info("Saved JWT token to file")
    except Exception as e:
        logger.error(f"Failed to save token: {e}")

def get_threats():
    """Fetch all threats from backend"""
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/threats?limit=500",
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Failed to fetch threats: {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        return []

def get_blocked_ips():
    """Get list of already blocked IPs"""
    try:
        headers = {"Authorization": f"Bearer {JWT_TOKEN}"}
        response = requests.get(
            f"{BACKEND_URL}/api/admin/ip-blocking/list",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return set(data.get("blocked_ips", []))
        else:
            logger.error(f"Failed to fetch blocked IPs: {response.status_code}")
            return set()
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {e}")
        return set()

def block_ip(ip_address, threat_data):
    """Block an IP via API"""
    try:
        risk_score = threat_data.get('severity_score') or threat_data.get('score') or 0
        
        payload = {
            "ip_address": ip_address,
            "threat_type": threat_data.get('type') or threat_data.get('category') or 'Unknown',
            "risk_category": threat_data.get('severity') or ('High' if risk_score >= 75 else 'Medium'),
            "risk_score": risk_score,
            "summary": threat_data.get('summary') or threat_data.get('title') or 'Auto-blocked',
            "reason": f"Auto-blocked by agent (score: {risk_score})"
        }
        
        headers = {
            "Authorization": f"Bearer {JWT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{BACKEND_URL}/api/block-threat",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 201:
            logger.info(f"BLOCKED: {ip_address} (Score: {risk_score})")
            return True
        elif response.status_code == 409:
            logger.debug(f"Already blocked: {ip_address}")
            return False
        else:
            logger.error(f"Failed to block {ip_address}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error blocking {ip_address}: {e}")
        return False

def extract_ip(threat):
    """Extract IP from threat data"""
    # Try indicator field first (usually contains IP)
    indicator = threat.get('indicator', '')
    if indicator and is_valid_ip(indicator):
        return indicator
    
    # Try summary field
    summary = threat.get('summary', '')
    if summary:
        ip = extract_ip_from_text(summary)
        if ip:
            return ip
    
    # Try type field
    threat_type = threat.get('type', '')
    if threat_type:
        ip = extract_ip_from_text(threat_type)
        if ip:
            return ip
    
    return None

def extract_ip_from_text(text):
    """Extract IP address from text using regex"""
    import re
    # IPv4 regex
    ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(ipv4_pattern, str(text))
    if match:
        ip = match.group(1)
        if is_valid_ip(ip):
            return ip
    return None

def is_valid_ip(ip):
    """Validate IP address"""
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        # Validate ranges and exclude critical IPs
        if all(0 <= int(p) <= 255 for p in parts):
            if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                return True
    return False

# ============================================================================
# MAIN BLOCKING LOOP
# ============================================================================

def run_blocking_agent():
    """Main blocking loop"""
    global JWT_TOKEN
    
    logger.info("=" * 70)
    logger.info("AUTO-BLOCKING AGENT STARTED")
    logger.info(f"Risk Threshold: {RISK_THRESHOLD}")
    logger.info(f"Daily Limit: {MAX_BLOCKS_PER_DAY} blocks")
    logger.info(f"Check Interval: {CHECK_INTERVAL} seconds")
    logger.info(f"Backend URL: {BACKEND_URL}")
    logger.info("=" * 70)
    
    # Load token
    JWT_TOKEN = load_token()
    if not JWT_TOKEN:
        logger.error("NO JWT TOKEN FOUND!")
        logger.error("Please set up authentication first.")
        logger.error("Run: python -c \"from auto_blocker import setup_token; setup_token()\"")
        return
    
    logger.info("JWT token loaded")
    
    # Track daily blocks
    last_reset_date = datetime.now().date()
    blocked_today = 0
    
    # Main loop
    try:
        while True:
            try:
                current_date = datetime.now().date()
                
                # Reset counter at midnight
                if current_date != last_reset_date:
                    last_reset_date = current_date
                    blocked_today = 0
                    logger.info(f"\n[NEW DAY] Daily block counter reset to 0")
                
                logger.info(f"\n[{datetime.now().strftime('%H:%M:%S')}] Checking for high-risk threats... (Blocked today: {blocked_today}/{MAX_BLOCKS_PER_DAY})")
                
                # Get threats
                threats = get_threats()
                if not threats:
                    logger.warning("No threats fetched")
                    time.sleep(CHECK_INTERVAL)
                    continue
                
                logger.info(f"Fetched {len(threats)} threats")
                
                # Get already blocked IPs
                blocked_ips = get_blocked_ips()
                logger.info(f"Currently blocked: {len(blocked_ips)} IPs")
                
                # Filter and block high-risk threats (stop at daily limit)
                blocked_count = 0
                high_risk_count = 0
                ip_threat_count = 0
                already_blocked_count = 0
                daily_limit_reached = False
                
                for threat in threats:
                    # Check if we've hit daily limit
                    if blocked_today >= MAX_BLOCKS_PER_DAY:
                        daily_limit_reached = True
                        logger.warning(f"Daily limit reached: {blocked_today}/{MAX_BLOCKS_PER_DAY} blocks")
                        break
                    
                    risk_score = threat.get('severity_score') or threat.get('score') or 0
                    threat_type = threat.get('type', 'unknown')
                    
                    # Check risk threshold
                    if risk_score >= RISK_THRESHOLD:
                        high_risk_count += 1
                        logger.debug(f"High-risk threat: {threat.get('indicator')} | Type: {threat_type} | Score: {risk_score}")
                        
                        # Only process IPv4 threats
                        if threat_type == 'IPv4':
                            ip_threat_count += 1
                            ip = threat.get('indicator')  # For IPv4, indicator IS the IP
                            if ip:
                                if ip in blocked_ips:
                                    already_blocked_count += 1
                                    logger.debug(f"Already blocked: {ip}")
                                else:
                                    if block_ip(ip, threat):
                                        blocked_count += 1
                                        blocked_today += 1
                
                logger.info(f"Analysis: {high_risk_count} high-risk (>={RISK_THRESHOLD}), {ip_threat_count} IPv4 type, {already_blocked_count} already blocked")
                
                if blocked_count > 0:
                    logger.info(f"SUMMARY: Blocked {blocked_count} new high-risk threat(s) today ({blocked_today}/{MAX_BLOCKS_PER_DAY})")
                elif daily_limit_reached:
                    logger.info(f"Daily limit reached: {blocked_today}/{MAX_BLOCKS_PER_DAY} blocks")
                else:
                    logger.info("No new high-risk threats to block")
                
                # Wait before next check
                logger.info(f"Next check in {CHECK_INTERVAL} seconds...")
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(CHECK_INTERVAL)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

def setup_token():
    """Interactive token setup"""
    print("\n" + "=" * 70)
    print("AUTO-BLOCKER TOKEN SETUP")
    print("=" * 70)
    print("\nTo get your JWT token:")
    print("1. Start the backend: cd backend && python app.py")
    print("2. Open http://localhost:3000")
    print("3. Login as admin/admin123")
    print("4. Open browser Developer Tools (F12)")
    print("5. Go to Application -> Cookies -> localhost:3000")
    print("6. Find 'auth_token' and copy the value")
    print("\nOr use this curl command to get a token:")
    print("curl -X POST http://localhost:5000/api/login \\")
    print("  -H 'Content-Type: application/json' \\")
    print("  -d '{\"username\": \"admin\", \"password\": \"admin123\"}'")
    print("\nThen copy the 'access_token' value from the response")
    print("=" * 70)
    
    token = input("\nPaste your JWT token here: ").strip()
    if token:
        save_token(token)
        print(f"Token saved to {TOKEN_FILE}")
    else:
        print("No token provided. Exiting.")

# ============================================================================
# SERVICE INTERFACE (for NSSM)
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "setup-token":
        setup_token()
    else:
        run_blocking_agent()
