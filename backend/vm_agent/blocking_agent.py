#!/usr/bin/env python3
"""
VM Blocking Agent for ThreatGuard CTI System
Runs on Kali Linux/Ubuntu VM to enforce IP blocking via iptables/ufw
Communicates with Windows host via WebSocket for real-time sync
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, Tuple, List, Dict, Any
import websockets
import requests

# Configuration
CONFIG_FILE = Path(__file__).parent / "agent_config.json"
BLOCKED_IPS_FILE = Path(__file__).parent / "blocked_ips.json"
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "blocking_agent.log"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [VM-AGENT] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class IPTablesManager:
    """Manages iptables/ufw firewall rules on Linux VM"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.use_ufw = self._check_ufw_available()
        self.chain_name = "THREATGUARD_BLOCK"
        self._load_blocked_ips()
        self._setup_custom_chain()
        logger.info(f"IPTablesManager initialized. Using {'ufw' if self.use_ufw else 'iptables'}")
    
    def _check_ufw_available(self) -> bool:
        """Check if ufw is available and active"""
        try:
            result = subprocess.run(
                ["which", "ufw"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                # Check if ufw is active
                status = subprocess.run(
                    ["sudo", "ufw", "status"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                return "Status: active" in status.stdout
            return False
        except Exception:
            return False
    
    def _setup_custom_chain(self):
        """Create custom iptables chain for ThreatGuard blocks"""
        if self.use_ufw:
            return  # UFW doesn't need custom chains
        
        try:
            # Create chain if it doesn't exist
            subprocess.run(
                ["sudo", "iptables", "-N", self.chain_name],
                capture_output=True,
                timeout=5
            )
            
            # Link chain to INPUT
            result = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-j", self.chain_name],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-j", self.chain_name],
                    capture_output=True,
                    timeout=5
                )
            
            logger.info(f"Custom iptables chain {self.chain_name} ready")
        except Exception as e:
            logger.error(f"Failed to setup custom chain: {e}")
    
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
    
    def block_ip(self, ip: str, reason: str = "Security threat") -> Tuple[bool, str]:
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
                logger.info(f"✅ Blocked IP {ip}: {reason}")
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
            return True, f"IP {ip} not in blocked list"
        
        try:
            if self.use_ufw:
                success, message = self._unblock_ip_ufw(ip)
            else:
                success, message = self._unblock_ip_iptables(ip)
            
            if success:
                self.blocked_ips.discard(ip)
                self._save_blocked_ips()
                logger.info(f"🔓 Unblocked IP {ip}")
                return True, f"Successfully unblocked {ip}"
            else:
                logger.error(f"Failed to unblock {ip}: {message}")
                return False, message
        
        except Exception as e:
            logger.error(f"Exception unblocking {ip}: {e}")
            return False, str(e)
    
    def _block_ip_ufw(self, ip: str) -> Tuple[bool, str]:
        """Block IP using ufw"""
        try:
            # Deny incoming from IP
            result = subprocess.run(
                ["sudo", "ufw", "deny", "from", ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"UFW rule added for {ip}")
                return True, "UFW rule added"
            else:
                error = result.stderr or result.stdout or "Unknown error"
                return False, f"UFW error: {error}"
        
        except subprocess.TimeoutExpired:
            return False, "UFW command timeout"
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_ufw(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using ufw"""
        try:
            result = subprocess.run(
                ["sudo", "ufw", "delete", "deny", "from", ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return True, "UFW rule removed"
            else:
                error = result.stderr or result.stdout or "Unknown error"
                return False, f"UFW error: {error}"
        
        except Exception as e:
            return False, str(e)
    
    def _block_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Block IP using iptables"""
        try:
            # Add to custom chain
            result = subprocess.run(
                ["sudo", "iptables", "-A", self.chain_name, "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Also block OUTPUT
                subprocess.run(
                    ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True,
                    timeout=10
                )
                logger.info(f"iptables rules added for {ip}")
                return True, "iptables rules added"
            else:
                error = result.stderr or result.stdout or "Unknown error"
                return False, f"iptables error: {error}"
        
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using iptables"""
        try:
            # Remove from custom chain
            subprocess.run(
                ["sudo", "iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=10
            )
            
            # Remove OUTPUT rule
            subprocess.run(
                ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True,
                timeout=10
            )
            
            return True, "iptables rules removed"
        
        except Exception as e:
            return False, str(e)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of all blocked IPs"""
        return list(self.blocked_ips)
    
    def sync_rules(self):
        """Restore all blocked IPs to firewall (after reboot/restart)"""
        logger.info(f"Syncing {len(self.blocked_ips)} blocked IPs to firewall...")
        restored = 0
        
        for ip in list(self.blocked_ips):
            success, _ = self.block_ip(ip, "Restored from persistence")
            if success:
                restored += 1
        
        logger.info(f"Restored {restored}/{len(self.blocked_ips)} firewall rules")
    
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
                    return True
        return False


class VMBlockingAgent:
    """Main agent for VM-side IP blocking with WebSocket sync"""
    
    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        self.iptables_manager = IPTablesManager()
        self.websocket = None
        self.running = False
        self.agent_id = self.config.get("agent_id", os.uname().nodename)
        
        # Restore firewall rules on startup
        self.iptables_manager.sync_rules()
    
    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load agent configuration"""
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        # Default configuration
        default_config = {
            "agent_id": os.uname().nodename,
            "websocket_url": "ws://192.168.1.100:8765",  # Replace with Windows host IP
            "api_url": "http://192.168.1.100:5000",
            "heartbeat_interval": 30,
            "reconnect_delay": 5,
            "jwt_token": None
        }
        
        # Save default config
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Created default config at {config_path}")
        except Exception as e:
            logger.error(f"Failed to save default config: {e}")
        
        return default_config
    
    async def connect_websocket(self):
        """Connect to Windows host WebSocket server"""
        ws_url = self.config.get("websocket_url")
        jwt_token = self.config.get("jwt_token")
        
        if not jwt_token:
            logger.error("No JWT token configured. Please set jwt_token in agent_config.json")
            return
        
        try:
            logger.info(f"Connecting to WebSocket server: {ws_url}")
            
            async with websockets.connect(ws_url) as websocket:
                self.websocket = websocket
                
                # Send authentication
                await websocket.send(json.dumps({
                    "token": jwt_token,
                    "client_type": "vm_agent",
                    "agent_id": self.agent_id
                }))
                
                # Wait for confirmation
                response = await websocket.recv()
                response_data = json.loads(response)
                
                if response_data.get("type") == "connected":
                    logger.info(f"✅ Connected to WebSocket server as VM agent")
                    self.running = True
                    
                    # Start heartbeat task
                    heartbeat_task = asyncio.create_task(self.send_heartbeat())
                    
                    # Listen for messages
                    try:
                        async for message in websocket:
                            await self.handle_message(message)
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("WebSocket connection closed")
                    finally:
                        heartbeat_task.cancel()
                        self.running = False
                else:
                    logger.error(f"Authentication failed: {response_data}")
        
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
            self.running = False
    
    async def handle_message(self, message: str):
        """Handle incoming WebSocket messages from host"""
        try:
            data = json.loads(message)
            msg_type = data.get("type")
            
            if msg_type == "block_ip":
                ip_address = data.get("ip_address")
                reason = data.get("reason", "Host-initiated block")
                
                logger.info(f"Received block command for {ip_address}")
                success, message = self.iptables_manager.block_ip(ip_address, reason)
                
                # Send confirmation back to host
                await self.send_confirmation("block", ip_address, success, message)
            
            elif msg_type == "unblock_ip":
                ip_address = data.get("ip_address")
                
                logger.info(f"Received unblock command for {ip_address}")
                success, message = self.iptables_manager.unblock_ip(ip_address)
                
                # Send confirmation back to host
                await self.send_confirmation("unblock", ip_address, success, message)
            
            elif msg_type == "sync_request":
                # Send full list of blocked IPs
                await self.send_status()
            
            elif msg_type == "ping":
                await self.websocket.send(json.dumps({"type": "pong"}))
        
        except json.JSONDecodeError:
            logger.error("Received invalid JSON message")
        except Exception as e:
            logger.error(f"Error handling message: {e}")
    
    async def send_confirmation(self, action: str, ip_address: str, 
                                success: bool, message: str):
        """Send confirmation of block/unblock action"""
        if not self.websocket:
            return
        
        try:
            await self.websocket.send(json.dumps({
                "type": f"{action}_confirmation",
                "ip_address": ip_address,
                "success": success,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            }))
        except Exception as e:
            logger.error(f"Failed to send confirmation: {e}")
    
    async def send_heartbeat(self):
        """Send periodic heartbeat and status"""
        interval = self.config.get("heartbeat_interval", 30)
        
        while self.running:
            try:
                await asyncio.sleep(interval)
                await self.send_status()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    async def send_status(self):
        """Send agent status to host"""
        if not self.websocket:
            return
        
        try:
            await self.websocket.send(json.dumps({
                "type": "vm_agent_status",
                "agent_id": self.agent_id,
                "status": "active",
                "blocked_ips_count": len(self.iptables_manager.blocked_ips),
                "blocked_ips": self.iptables_manager.get_blocked_ips(),
                "firewall_type": "ufw" if self.iptables_manager.use_ufw else "iptables",
                "timestamp": datetime.utcnow().isoformat()
            }))
        except Exception as e:
            logger.error(f"Failed to send status: {e}")
    
    async def run(self):
        """Main run loop with auto-reconnect"""
        reconnect_delay = self.config.get("reconnect_delay", 5)
        
        while True:
            try:
                await self.connect_websocket()
            except Exception as e:
                logger.error(f"Connection failed: {e}")
            
            if self.running:
                break
            
            logger.info(f"Reconnecting in {reconnect_delay} seconds...")
            await asyncio.sleep(reconnect_delay)


def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("ThreatGuard VM Blocking Agent Starting...")
    logger.info("=" * 60)
    
    agent = VMBlockingAgent()
    
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("\nAgent shutting down...")
    except Exception as e:
        logger.error(f"Agent error: {e}")
        raise


if __name__ == "__main__":
    main()
