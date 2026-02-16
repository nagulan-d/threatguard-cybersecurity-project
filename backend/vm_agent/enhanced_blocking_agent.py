#!/usr/bin/env python3
"""
Enhanced Kali/Linux Blocking Agent with Bi-directional Sync
Runs on Kali Linux/Ubuntu VM to enforce IP blocking via iptables/ufw
Communicates with Windows host via REST API for real-time sync
Includes local API server for receiving blocking commands
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Set, Tuple, List, Dict, Any
from flask import Flask, request, jsonify
import requests
from functools import wraps

# Configuration
CONFIG_FILE = Path(__file__).parent / "agent_config.json"
BLOCKED_IPS_FILE = Path(__file__).parent / "blocked_ips.json"
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "blocking_agent.log"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [KALI-AGENT] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Flask API
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global variables
blocked_ips: Set[str] = set()
blocked_ips_lock = threading.Lock()
api_token = os.getenv("BLOCKING_API_TOKEN", "default_token")


class KaliIPTablesManager:
    """Manages iptables/ufw firewall rules on Linux VM"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.use_ufw = self._check_ufw_available()
        self.chain_name = "THREATGUARD"
        self._load_blocked_ips()
        self._setup_firewall()
        logger.info(f"KaliIPTablesManager initialized. Using {'ufw' if self.use_ufw else 'iptables'}")
    
    def _check_ufw_available(self) -> bool:
        """Check if ufw is available and active"""
        try:
            result = subprocess.run(
                ["which", "ufw"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                status = subprocess.run(
                    ["sudo", "ufw", "status"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                return "Status: active" in status.stdout or "Status: inactive" in status.stdout
            return False
        except Exception:
            return False
    
    def _setup_firewall(self):
        """Setup firewall for blocking"""
        if self.use_ufw:
            logger.info("Using UFW for firewall management")
        else:
            self._setup_iptables_chain()
    
    def _setup_iptables_chain(self):
        """Create custom iptables chain for ThreatGuard blocks"""
        try:
            # Check if chain exists
            result = subprocess.run(
                ["sudo", "iptables", "-L", self.chain_name, "-n"],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                # Create new chain
                subprocess.run(
                    ["sudo", "iptables", "-N", self.chain_name],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                
                # Link to INPUT chain
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-j", self.chain_name],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                
                # Link to OUTPUT chain
                subprocess.run(
                    ["sudo", "iptables", "-I", "OUTPUT", "-j", self.chain_name],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
            
            logger.info(f"iptables chain {self.chain_name} is ready")
        
        except Exception as e:
            logger.error(f"Failed to setup iptables chain: {e}")
    
    def _load_blocked_ips(self):
        """Load blocked IPs from persistent storage"""
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked_ips', []))
                logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from storage")
            except Exception as e:
                logger.error(f"Failed to load blocked IPs: {e}")
                self.blocked_ips = set()
    
    def _save_blocked_ips(self):
        """Save blocked IPs to persistent storage"""
        try:
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_ips),
                    'last_updated': datetime.utcnow().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save blocked IPs: {e}")
    
    def block_ip(self, ip: str, rule_type: str = "THREATGUARD") -> Tuple[bool, str]:
        """Block an IP address using firewall rules"""
        if ip in self.blocked_ips:
            return True, f"IP {ip} already blocked"
        
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP format: {ip}"
        
        try:
            if self.use_ufw:
                success, message = self._block_ip_ufw(ip)
            else:
                success, message = self._block_ip_iptables(ip)
            
            if success:
                self.blocked_ips.add(ip)
                self._save_blocked_ips()
                logger.info(f"✅ Blocked IP {ip}")
                return True, f"Successfully blocked {ip}"
            else:
                logger.error(f"❌ Failed to block {ip}: {message}")
                return False, message
        
        except Exception as e:
            logger.error(f"Exception blocking {ip}: {e}")
            return False, str(e)
    
    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return False, f"IP {ip} not in blocked list"
        
        try:
            if self.use_ufw:
                success, message = self._unblock_ip_ufw(ip)
            else:
                success, message = self._unblock_ip_iptables(ip)
            
            if success:
                self.blocked_ips.discard(ip)
                self._save_blocked_ips()
                logger.info(f"✅ Unblocked IP {ip}")
                return True, f"Successfully unblocked {ip}"
            else:
                logger.error(f"❌ Failed to unblock {ip}: {message}")
                return False, message
        
        except Exception as e:
            logger.error(f"Exception unblocking {ip}: {e}")
            return False, str(e)
    
    def _block_ip_ufw(self, ip: str) -> Tuple[bool, str]:
        """Block IP using ufw"""
        try:
            # Inbound
            subprocess.run(
                ["sudo", "ufw", "deny", "from", ip],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            # Outbound
            subprocess.run(
                ["sudo", "ufw", "deny", "to", ip],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            return True, "UFW rules created"
        
        except Exception as e:
            return False, str(e)
    
    def _block_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Block IP using iptables"""
        try:
            rules = []
            
            # Inbound rule
            cmd_in = ["sudo", "iptables", "-I", self.chain_name, "-s", ip, "-j", "DROP"]
            result = subprocess.run(
                cmd_in,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                rules.append(f"iptables -s {ip} -j DROP (inbound)")
            else:
                raise Exception(f"Inbound rule failed: {result.stderr}")
            
            # Outbound rule
            cmd_out = ["sudo", "iptables", "-I", self.chain_name, "-d", ip, "-j", "DROP"]
            result = subprocess.run(
                cmd_out,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                rules.append(f"iptables -d {ip} -j DROP (outbound)")
            else:
                # Rollback inbound
                subprocess.run(cmd_in.replace("-I", "-D"), capture_output=True, timeout=5)
                raise Exception(f"Outbound rule failed: {result.stderr}")
            
            return True, f"iptables rules created: {'; '.join(rules)}"
        
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_ufw(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using ufw"""
        try:
            subprocess.run(
                ["sudo", "ufw", "delete", "deny", "from", ip],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            subprocess.run(
                ["sudo", "ufw", "delete", "deny", "to", ip],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            return True, "UFW rules removed"
        
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using iptables"""
        try:
            # Remove inbound rule
            subprocess.run(
                ["sudo", "iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            # Remove outbound rule
            subprocess.run(
                ["sudo", "iptables", "-D", self.chain_name, "-d", ip, "-j", "DROP"],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            return True, "iptables rules removed"
        
        except Exception as e:
            return False, str(e)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of all blocked IPs"""
        return list(self.blocked_ips)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address (IPv4 or IPv6)"""
        import re
        
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            try:
                parts = ip.split('.')
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        # IPv6
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv6_pattern, ip))


# Initialize firewall manager
firewall_manager = KaliIPTablesManager()


# ============= API AUTHENTICATION =============

def require_api_token(f):
    """Require valid API token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '')
        if not token.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid token"}), 401
        
        if token[7:] != api_token:
            return jsonify({"error": "Invalid token"}), 403
        
        return f(*args, **kwargs)
    
    return decorated


# ============= REST API ENDPOINTS =============

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "KaliBlockingAgent",
        "blocked_ips_count": len(firewall_manager.blocked_ips),
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route('/api/blocking/block', methods=['POST'])
@require_api_token
def block_endpoint():
    """Block an IP address"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        threat_category = data.get('threat_category', 'Unknown')
        risk_score = data.get('risk_score', 0)
        reason = data.get('reason', 'Security threat')
        
        if not ip_address:
            return jsonify({"error": "Missing ip_address"}), 400
        
        logger.info(f"Blocking request: {ip_address} (Risk: {risk_score}, Category: {threat_category})")
        
        with blocked_ips_lock:
            success, message = firewall_manager.block_ip(ip_address)
        
        if success:
            return jsonify({
                "success": True,
                "ip_address": ip_address,
                "message": message,
                "rules": [f"Blocked {ip_address} via {firewall_manager.use_ufw and 'ufw' or 'iptables'}"],
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                "success": False,
                "ip_address": ip_address,
                "error": message,
                "timestamp": datetime.utcnow().isoformat()
            }), 400
    
    except Exception as e:
        logger.error(f"Error blocking IP: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/blocking/unblock', methods=['POST'])
@require_api_token
def unblock_endpoint():
    """Unblock an IP address"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({"error": "Missing ip_address"}), 400
        
        logger.info(f"Unblocking request: {ip_address}")
        
        with blocked_ips_lock:
            success, message = firewall_manager.unblock_ip(ip_address)
        
        if success:
            return jsonify({
                "success": True,
                "ip_address": ip_address,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                "success": False,
                "ip_address": ip_address,
                "error": message,
                "timestamp": datetime.utcnow().isoformat()
            }), 400
    
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/blocking/list', methods=['GET'])
@require_api_token
def list_blocked():
    """Get list of blocked IPs"""
    try:
        with blocked_ips_lock:
            blocked = firewall_manager.get_blocked_ips()
        
        return jsonify({
            "count": len(blocked),
            "blocked_ips": blocked,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error listing blocked IPs: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/blocking/status/<ip_address>', methods=['GET'])
@require_api_token
def status_endpoint(ip_address):
    """Check if an IP is blocked"""
    try:
        with blocked_ips_lock:
            is_blocked = ip_address in firewall_manager.blocked_ips
        
        return jsonify({
            "ip_address": ip_address,
            "is_blocked": is_blocked,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error checking status: {e}")
        return jsonify({"error": str(e)}), 500


# ============= MAIN =============

def main():
    """Main entry point"""
    api_port = int(os.getenv("BLOCKING_AGENT_PORT", "5001"))
    debug_mode = os.getenv("DEBUG", "false").lower() == "true"
    
    logger.info(f"🚀 Starting Kali Blocking Agent on port {api_port}")
    logger.info(f"API Token required: Bearer {api_token[:20]}...")
    
    try:
        app.run(
            host='0.0.0.0',
            port=api_port,
            debug=debug_mode,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
