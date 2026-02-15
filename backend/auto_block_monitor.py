"""
Automated High-Severity Threat Blocking Monitor
Continuously monitors threat database and automatically blocks high-risk IPs
Runs as a background service with configurable thresholds
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Set
import requests
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))

load_dotenv()

# Configuration
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "true").lower() == "true"
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", 75))  # Risk score >= 75
CHECK_INTERVAL = int(os.getenv("AUTO_BLOCK_CHECK_INTERVAL", 120))  # Seconds
MAX_BLOCKS_PER_CYCLE = int(os.getenv("AUTO_BLOCK_MAX_PER_CYCLE", 5))
BLOCK_DELAY = int(os.getenv("AUTO_BLOCK_DELAY", 10))  # Delay between blocks
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")

# JWT token for API authentication
TOKEN_FILE = Path(__file__).parent / ".auto_blocker_token"

# Logging setup
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "auto_block_monitor.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [AUTO-BLOCK] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AutoBlockMonitor:
    """Monitor and automatically block high-severity threats"""
    
    def __init__(self):
        self.jwt_token = self._load_token()
        self.blocked_ips: Set[str] = set()
        self.seen_threats: Set[str] = set()
        self.block_history_file = Path(__file__).parent / "auto_block_history.json"
        self.running = False
        self._load_history()
        
        logger.info("AutoBlockMonitor initialized")
        logger.info(f"Threshold: {AUTO_BLOCK_THRESHOLD}, Interval: {CHECK_INTERVAL}s")
    
    def _load_token(self) -> str:
        """Load JWT token from file"""
        if TOKEN_FILE.exists():
            try:
                with open(TOKEN_FILE, 'r') as f:
                    token = f.read().strip()
                    if token:
                        logger.info("Loaded JWT token")
                        return token
            except Exception as e:
                logger.error(f"Failed to load token: {e}")
        
        logger.warning("No JWT token found - auto-blocking will not work")
        logger.info(f"Please create {TOKEN_FILE} with admin JWT token")
        return ""
    
    def _load_history(self):
        """Load previously blocked IPs from history"""
        if self.block_history_file.exists():
            try:
                with open(self.block_history_file, 'r') as f:
                    history = json.load(f)
                    self.blocked_ips = set(history.get('blocked_ips', []))
                    self.seen_threats = set(history.get('seen_threats', []))
                    
                logger.info(f"Loaded history: {len(self.blocked_ips)} blocked IPs, "
                           f"{len(self.seen_threats)} seen threats")
            except Exception as e:
                logger.error(f"Failed to load history: {e}")
    
    def _save_history(self):
        """Save blocking history"""
        try:
            with open(self.block_history_file, 'w') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_ips),
                    'seen_threats': list(self.seen_threats),
                    'last_updated': datetime.utcnow().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def get_high_severity_threats(self) -> List[Dict[str, Any]]:
        """Fetch high-severity threats from backend API"""
        try:
            response = requests.get(
                f"{BACKEND_URL}/api/threats",
                params={"limit": 100},
                timeout=10
            )
            
            if response.status_code == 200:
                threats = response.json()
                
                # Filter for high severity
                high_severity = []
                for threat in threats:
                    risk_score = threat.get('severity_score') or threat.get('score') or 0
                    severity = threat.get('severity', '').lower()
                    
                    # High severity: score >= threshold OR severity = "high"
                    if risk_score >= AUTO_BLOCK_THRESHOLD or severity == 'high':
                        high_severity.append(threat)
                
                logger.info(f"Found {len(high_severity)} high-severity threats out of {len(threats)} total")
                return high_severity
            else:
                logger.error(f"Failed to fetch threats: {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"Error fetching threats: {e}")
            return []
    
    def extract_ip_from_threat(self, threat: Dict[str, Any]) -> str:
        """Extract IP address from threat data"""
        # Try indicator field
        indicator = threat.get('indicator', '')
        if self._is_valid_ip(indicator):
            return indicator
        
        # Try ip_address field
        ip = threat.get('ip_address', '')
        if self._is_valid_ip(ip):
            return ip
        
        # Try extracting from summary or title
        summary = threat.get('summary', '') + ' ' + threat.get('title', '')
        import re
        ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ipv4_pattern, summary)
        if match:
            ip = match.group(1)
            if self._is_valid_ip(ip):
                return ip
        
        return ""
    
    def block_threat(self, threat: Dict[str, Any], ip_address: str) -> bool:
        """Block a specific threat IP via backend API"""
        try:
            risk_score = threat.get('severity_score') or threat.get('score') or 0
            
            payload = {
                "ip_address": ip_address,
                "threat_type": threat.get('type') or threat.get('category') or 'Unknown',
                "risk_category": threat.get('severity') or 'High',
                "risk_score": risk_score,
                "summary": threat.get('summary') or threat.get('title') or 'Auto-blocked high-severity threat',
                "reason": f"Automatically blocked - Risk score: {risk_score}, Severity: {threat.get('severity')}"
            }
            
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"{BACKEND_URL}/api/admin/block-threat-auto",
                json=payload,
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 201:
                logger.info(f"BLOCKED: {ip_address} (Score: {risk_score})")
                self.blocked_ips.add(ip_address)
                self._save_history()
                return True
            
            elif response.status_code == 409:
                logger.debug(f"Already blocked: {ip_address}")
                self.blocked_ips.add(ip_address)
                return False
            
            else:
                logger.error(f"Failed to block {ip_address}: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking {ip_address}: {e}")
            return False
    
    def process_threats(self):
        """Process and block high-severity threats"""
        logger.info("=" * 60)
        logger.info("Starting threat processing cycle...")
        
        # Get high-severity threats
        threats = self.get_high_severity_threats()
        
        if not threats:
            logger.info("No high-severity threats found")
            return
        
        # Filter out already blocked and seen threats
        new_threats = []
        for threat in threats:
            threat_id = str(threat.get('id', '')) or threat.get('indicator', '')
            
            if threat_id in self.seen_threats:
                continue
            
            ip_address = self.extract_ip_from_threat(threat)
            if not ip_address:
                logger.debug(f"No valid IP in threat: {threat.get('indicator', 'Unknown')}")
                self.seen_threats.add(threat_id)
                continue
            
            if ip_address in self.blocked_ips:
                logger.debug(f"IP {ip_address} already blocked")
                self.seen_threats.add(threat_id)
                continue
            
            new_threats.append((threat, ip_address, threat_id))
        
        if not new_threats:
            logger.info("No new threats to block")
            return
        
        logger.info(f"Found {len(new_threats)} new high-severity threats to block")
        
        # Block threats one by one with delay
        blocked_count = 0
        for threat, ip_address, threat_id in new_threats[:MAX_BLOCKS_PER_CYCLE]:
            logger.info(f"\nProcessing threat: {threat.get('indicator', 'Unknown')}")
            logger.info(f"  IP: {ip_address}")
            logger.info(f"  Type: {threat.get('type', 'Unknown')}")
            logger.info(f"  Severity: {threat.get('severity', 'Unknown')}")
            logger.info(f"  Score: {threat.get('severity_score') or threat.get('score')}")
            
            # Attempt to block
            if self.block_threat(threat, ip_address):
                blocked_count += 1
                
                # Add delay between blocks
                if blocked_count < MAX_BLOCKS_PER_CYCLE:
                    logger.info(f"Waiting {BLOCK_DELAY} seconds before next block...")
                    time.sleep(BLOCK_DELAY)
            
            # Mark as seen
            self.seen_threats.add(threat_id)
        
        self._save_history()
        
        logger.info("=" * 60)
        logger.info(f"Cycle complete: {blocked_count} new IPs blocked")
        logger.info(f"Total blocked IPs: {len(self.blocked_ips)}")
        logger.info("=" * 60)
    
    def run(self):
        """Main monitoring loop"""
        logger.info("=" * 60)
        logger.info("Auto-Block Monitor Starting...")
        logger.info(f"Enabled: {AUTO_BLOCK_ENABLED}")
        logger.info(f"Risk Threshold: {AUTO_BLOCK_THRESHOLD}")
        logger.info(f"Check Interval: {CHECK_INTERVAL} seconds")
        logger.info(f"Max Blocks/Cycle: {MAX_BLOCKS_PER_CYCLE}")
        logger.info("=" * 60)
        
        if not AUTO_BLOCK_ENABLED:
            logger.warning("Auto-blocking is DISABLED - set AUTO_BLOCK_ENABLED=true to enable")
            return
        
        if not self.jwt_token:
            logger.error("No JWT token available - cannot proceed")
            logger.info("Create an admin user and save the JWT token to .auto_blocker_token")
            return
        
        self.running = True
        
        try:
            while self.running:
                try:
                    self.process_threats()
                except Exception as e:
                    logger.error(f"Error in processing cycle: {e}", exc_info=True)
                
                # Wait for next cycle
                logger.info(f"\nSleeping for {CHECK_INTERVAL} seconds until next check...\n")
                time.sleep(CHECK_INTERVAL)
        
        except KeyboardInterrupt:
            logger.info("\n\nShutting down auto-block monitor...")
            self.running = False
        
        except Exception as e:
            logger.error(f"Fatal error in monitor: {e}", exc_info=True)
            raise
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format"""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                # Exclude critical IPs
                if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                    # Exclude private IP ranges (optional - remove if you want to block private IPs)
                    if not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.16.'):
                        return True
        return False


def main():
    """Main entry point"""
    monitor = AutoBlockMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
