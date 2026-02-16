"""
Blocking Synchronization Service for ThreatGuard
Coordinates IP blocking across Windows Host and Kali Linux VM
Maintains centralized blocked IP database with real-time sync
"""

import logging
import json
import requests
import subprocess
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from enum import Enum
import hashlib
import os

logger = logging.getLogger(__name__)

class SyncStatus(Enum):
    """Enum for sync statuses"""
    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class BlockActionStatus(Enum):
    """Enum for individual blocking action status"""
    PENDING = "pending"
    BLOCKED = "blocked"
    UNBLOCKED = "unblocked"
    FAILED = "failed"


class BlockingSyncService:
    """Main service for coordinating IP blocking across systems"""
    
    def __init__(self, app=None, db=None):
        """Initialize the blocking sync service"""
        self.app = app
        self.db = db
        self.sync_history: Dict[str, dict] = {}
        self.blocked_ips_cache: set = set()
        self.sync_lock = threading.Lock()
        
        # Config defaults
        self.linux_api_host = os.getenv("LINUX_VM_HOST", "192.168.1.100")
        self.linux_api_port = int(os.getenv("LINUX_VM_PORT", "5001"))
        self.linux_api_token = os.getenv("LINUX_VM_API_TOKEN", "")
        self.sync_timeout = int(os.getenv("SYNC_TIMEOUT", "30"))
        self.use_ssh = os.getenv("USE_SSH_BLOCKING", "false").lower() == "true"
        self.ssh_key_path = os.getenv("SSH_KEY_PATH", "")
        self.ssh_user = os.getenv("SSH_USER", "kali")
        
        logger.info(f"BlockingSyncService initialized. Linux host: {self.linux_api_host}:{self.linux_api_port}")
    
    def block_ip_synchronized(self, ip: str, threat_data: dict, user=None) -> Dict:
        """
        Synchronously block an IP on both Windows and Kali VM
        
        Args:
            ip: IP address to block
            threat_data: Dictionary with threat information
            user: User object performing the action
            
        Returns:
            Dictionary with sync result status
        """
        sync_result = {
            "ip": ip,
            "sync_id": self._generate_sync_id(ip),
            "timestamp": datetime.utcnow().isoformat(),
            "action": "block",
            "status": "initiated",
            "windows_status": "pending",
            "linux_status": "pending",
            "errors": []
        }
        
        try:
            with self.sync_lock:
                # Check if already blocked
                if self._is_ip_already_blocked(ip):
                    sync_result["status"] = "skipped"
                    sync_result["message"] = f"IP {ip} already blocked"
                    logger.warning(f"IP {ip} already in blocked list")
                    return sync_result
                
                # Create sync record in database
                from models import BlockingSyncRecord, db as model_db
                sync_record = BlockingSyncRecord(
                    ip_address=ip,
                    action="block",
                    reason=threat_data.get("reason", "Security threat"),
                    risk_score=threat_data.get("risk_score", 0.0),
                    threat_category=threat_data.get("category", "Unknown"),
                    initiated_by_user_id=user.id if user else None,
                    sync_status="in-progress"
                )
                if self.db:
                    self.db.session.add(sync_record)
                    self.db.session.commit()
                
                sync_result["sync_record_id"] = sync_record.id
                
                # Block on Windows first
                logger.info(f"🔒 Blocking IP {ip} on Windows...")
                windows_result = self._block_ip_windows(ip, threat_data)
                sync_result["windows_status"] = "blocked" if windows_result["success"] else "failed"
                if not windows_result["success"]:
                    sync_result["errors"].append(f"Windows: {windows_result['error']}")
                else:
                    sync_result["windows_rule"] = windows_result.get("rule_name", "")
                    if self.db:
                        sync_record.windows_status = "blocked"
                        sync_record.windows_rule_name = windows_result.get("rule_name", "")
                        sync_record.windows_blocked_at = datetime.utcnow()
                
                # Block on Linux/Kali
                logger.info(f"🔒 Blocking IP {ip} on Linux/Kali...")
                linux_result = self._block_ip_linux(ip, threat_data)
                sync_result["linux_status"] = "blocked" if linux_result["success"] else "failed"
                if not linux_result["success"]:
                    sync_result["errors"].append(f"Linux: {linux_result['error']}")
                    # Optionally rollback Windows if Linux fails
                    if not threat_data.get("allow_partial_block", False):
                        logger.warning(f"Linux blocking failed for {ip}. Rolling back Windows...")
                        self._unblock_ip_windows(ip)
                        sync_result["windows_status"] = "rolled_back"
                else:
                    sync_result["linux_rules"] = linux_result.get("rules", [])
                    if self.db:
                        sync_record.linux_status = "blocked"
                        sync_record.linux_rules = json.dumps(linux_result.get("rules", []))
                        sync_record.linux_blocked_at = datetime.utcnow()
                
                # Log sync completion
                if sync_result["windows_status"] == "blocked" and sync_result["linux_status"] == "blocked":
                    sync_result["status"] = "completed"
                    if self.db:
                        sync_record.sync_status = "completed"
                        sync_record.sync_completed = True
                        sync_record.completed_at = datetime.utcnow()
                    self._log_sync_event(ip, "block_completed", "coordinator", "IP blocked on both systems", "success", sync_record.id if self.db else None)
                    logger.info(f"✅ IP {ip} successfully blocked on Windows and Linux")
                elif sync_result["windows_status"] == "blocked" or sync_result["linux_status"] == "blocked":
                    sync_result["status"] = "partial"
                    if self.db:
                        sync_record.sync_status = "partial"
                    logger.warning(f"⚠️ IP {ip} partially blocked (Windows: {sync_result['windows_status']}, Linux: {sync_result['linux_status']})")
                else:
                    sync_result["status"] = "failed"
                    if self.db:
                        sync_record.sync_status = "failed"
                    logger.error(f"❌ Failed to block IP {ip} on both systems")
                
                if self.db:
                    self.db.session.commit()
                
                # Add to cache
                if sync_result["windows_status"] == "blocked" or sync_result["linux_status"] == "blocked":
                    self.blocked_ips_cache.add(ip)
                
                return sync_result
        
        except Exception as e:
            logger.error(f"Exception during sync block of {ip}: {e}", exc_info=True)
            sync_result["status"] = "failed"
            sync_result["errors"].append(str(e))
            return sync_result
    
    def unblock_ip_synchronized(self, ip: str, user=None) -> Dict:
        """Synchronously unblock an IP on both systems"""
        sync_result = {
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "action": "unblock",
            "status": "initiated",
            "windows_status": "pending",
            "linux_status": "pending",
            "errors": []
        }
        
        try:
            with self.sync_lock:
                if ip not in self.blocked_ips_cache:
                    sync_result["status"] = "skipped"
                    sync_result["message"] = f"IP {ip} is not blocked"
                    logger.warning(f"IP {ip} not in blocked list")
                    return sync_result
                
                # Create sync record
                from models import BlockingSyncRecord
                sync_record = None
                if self.db:
                    sync_record = BlockingSyncRecord(
                        ip_address=ip,
                        action="unblock",
                        initiated_by_user_id=user.id if user else None,
                        sync_status="in-progress"
                    )
                    self.db.session.add(sync_record)
                    self.db.session.commit()
                
                # Unblock on Windows
                logger.info(f"🔓 Unblocking IP {ip} on Windows...")
                windows_result = self._unblock_ip_windows(ip)
                sync_result["windows_status"] = "unblocked" if windows_result["success"] else "failed"
                if not windows_result["success"]:
                    sync_result["errors"].append(f"Windows: {windows_result['error']}")
                
                # Unblock on Linux
                logger.info(f"🔓 Unblocking IP {ip} on Linux...")
                linux_result = self._unblock_ip_linux(ip)
                sync_result["linux_status"] = "unblocked" if linux_result["success"] else "failed"
                if not linux_result["success"]:
                    sync_result["errors"].append(f"Linux: {linux_result['error']}")
                
                # Finalize sync record
                if self.db and sync_record:
                    sync_record.windows_status = sync_result["windows_status"]
                    sync_record.linux_status = sync_result["linux_status"]
                    if sync_result["windows_status"] == "unblocked" and sync_result["linux_status"] == "unblocked":
                        sync_record.sync_status = "completed"
                        sync_record.sync_completed = True
                        sync_result["status"] = "completed"
                    else:
                        sync_record.sync_status = "partial"
                        sync_result["status"] = "partial"
                    sync_record.completed_at = datetime.utcnow()
                    self.db.session.commit()
                
                # Remove from cache
                self.blocked_ips_cache.discard(ip)
                
                logger.info(f"✅ IP {ip} unblocked on both systems")
                return sync_result
        
        except Exception as e:
            logger.error(f"Exception during sync unblock of {ip}: {e}", exc_info=True)
            sync_result["status"] = "failed"
            sync_result["errors"].append(str(e))
            return sync_result
    
    def _block_ip_windows(self, ip: str, threat_data: dict) -> Dict:
        """Block IP using Windows Firewall"""
        try:
            rule_name_in = f"TG_BLOCK_{ip.replace('.', '_')}_IN"
            rule_name_out = f"TG_BLOCK_{ip.replace('.', '_')}_OUT"
            
            # Inbound rule
            cmd_in = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name_in}" '
                f'dir=in action=block remoteip={ip} '
                f'enable=yes profile=any '
                f'description="Auto-blocked by ThreatGuard | Risk: {threat_data.get("risk_score", 0)}"'
            )
            
            result_in = subprocess.run(
                cmd_in,
                shell=True,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result_in.returncode != 0:
                error_msg = result_in.stderr or result_in.stdout or "Unknown error"
                logger.error(f"Windows inbound rule error for {ip}: {error_msg}")
                return {"success": False, "error": f"Inbound rule failed: {error_msg}"}
            
            # Outbound rule
            cmd_out = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name_out}" '
                f'dir=out action=block remoteip={ip} '
                f'enable=yes profile=any '
                f'description="Auto-blocked by ThreatGuard | Risk: {threat_data.get("risk_score", 0)}"'
            )
            
            result_out = subprocess.run(
                cmd_out,
                shell=True,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result_out.returncode != 0:
                # Rollback inbound rule
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{rule_name_in}"',
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                error_msg = result_out.stderr or result_out.stdout or "Unknown error"
                logger.error(f"Windows outbound rule error for {ip}: {error_msg}")
                return {"success": False, "error": f"Outbound rule failed: {error_msg}"}
            
            logger.info(f"✅ Windows Firewall rules created for {ip}: {rule_name_in}, {rule_name_out}")
            return {
                "success": True,
                "rule_name": f"{rule_name_in};{rule_name_out}",
                "rules": [rule_name_in, rule_name_out]
            }
        
        except Exception as e:
            logger.error(f"Exception blocking {ip} on Windows: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _unblock_ip_windows(self, ip: str) -> Dict:
        """Unblock IP on Windows Firewall"""
        try:
            rule_name_in = f"TG_BLOCK_{ip.replace('.', '_')}_IN"
            rule_name_out = f"TG_BLOCK_{ip.replace('.', '_')}_OUT"
            
            for rule_name in [rule_name_in, rule_name_out]:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                
                if result.returncode != 0 and "does not exist" not in result.stderr:
                    logger.warning(f"Rule {rule_name} not found or error deleting")
            
            logger.info(f"✅ Windows Firewall rules removed for {ip}")
            return {"success": True}
        
        except Exception as e:
            logger.error(f"Exception unblocking {ip} on Windows: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _block_ip_linux(self, ip: str, threat_data: dict) -> Dict:
        """Block IP on Linux/Kali using API or SSH"""
        try:
            if self.use_ssh and self.ssh_key_path:
                return self._block_ip_linux_ssh(ip, threat_data)
            else:
                return self._block_ip_linux_api(ip, threat_data)
        
        except Exception as e:
            logger.error(f"Exception blocking {ip} on Linux: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _block_ip_linux_api(self, ip: str, threat_data: dict) -> Dict:
        """Block IP on Linux via REST API"""
        try:
            url = f"http://{self.linux_api_host}:{self.linux_api_port}/api/blocking/block"
            
            payload = {
                "ip_address": ip,
                "threat_category": threat_data.get("category", "Unknown"),
                "risk_score": threat_data.get("risk_score", 0),
                "reason": threat_data.get("reason", "Security threat"),
                "rule_type": "THREATGUARD",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.linux_api_token}" if self.linux_api_token else ""
            }
            
            logger.debug(f"Sending block request to Linux API: {url}")
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.sync_timeout
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"✅ Linux API block successful for {ip}: {result}")
                return {
                    "success": True,
                    "rules": result.get("rules", []),
                    "message": result.get("message", "")
                }
            else:
                error_msg = response.text or f"HTTP {response.status_code}"
                logger.error(f"Linux API error for {ip}: {error_msg}")
                return {"success": False, "error": error_msg}
        
        except requests.exceptions.Timeout:
            logger.error(f"Linux API timeout for {ip}")
            return {"success": False, "error": "Linux API timeout"}
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Linux API at {self.linux_api_host}:{self.linux_api_port}")
            return {"success": False, "error": "Cannot connect to Linux API"}
        except Exception as e:
            logger.error(f"Exception in Linux API blocking for {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    def _block_ip_linux_ssh(self, ip: str, threat_data: dict) -> Dict:
        """Block IP on Linux via SSH"""
        try:
            # This would execute iptables commands via SSH
            # Implementation depends on specific SSH setup
            logger.warning("SSH blocking not fully implemented yet")
            return {"success": False, "error": "SSH blocking not yet implemented"}
        
        except Exception as e:
            logger.error(f"Exception in SSH blocking for {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    def _unblock_ip_linux(self, ip: str) -> Dict:
        """Unblock IP on Linux"""
        try:
            if self.use_ssh and self.ssh_key_path:
                return self._unblock_ip_linux_ssh(ip)
            else:
                return self._unblock_ip_linux_api(ip)
        
        except Exception as e:
            logger.error(f"Exception unblocking {ip} on Linux: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _unblock_ip_linux_api(self, ip: str) -> Dict:
        """Unblock IP on Linux via REST API"""
        try:
            url = f"http://{self.linux_api_host}:{self.linux_api_port}/api/blocking/unblock"
            
            payload = {
                "ip_address": ip,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.linux_api_token}" if self.linux_api_token else ""
            }
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.sync_timeout
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"✅ Linux API unblock successful for {ip}")
                return {"success": True}
            else:
                error_msg = response.text or f"HTTP {response.status_code}"
                logger.error(f"Linux API unblock error for {ip}: {error_msg}")
                return {"success": False, "error": error_msg}
        
        except Exception as e:
            logger.error(f"Exception in Linux API unblock for {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    def _unblock_ip_linux_ssh(self, ip: str) -> Dict:
        """Unblock IP on Linux via SSH"""
        try:
            logger.warning("SSH unblocking not fully implemented yet")
            return {"success": False, "error": "SSH unblocking not yet implemented"}
        
        except Exception as e:
            logger.error(f"Exception in SSH unblocking for {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    def _is_ip_already_blocked(self, ip: str) -> bool:
        """Check if IP is already blocked"""
        # Check cache first
        if ip in self.blocked_ips_cache:
            return True
        
        # Check database if available
        if self.db:
            try:
                from models import BlockingSyncRecord
                record = BlockingSyncRecord.query.filter_by(
                    ip_address=ip,
                    action="block",
                    sync_status="completed"
                ).first()
                return record is not None
            except Exception as e:
                logger.warning(f"Database check failed for {ip}: {e}")
        
        return False
    
    def _generate_sync_id(self, ip: str) -> str:
        """Generate unique sync ID"""
        timestamp = datetime.utcnow().isoformat()
        data = f"{ip}-{timestamp}".encode()
        return hashlib.sha256(data).hexdigest()[:12]
    
    def _log_sync_event(self, ip: str, action: str, component: str, message: str, status: str, sync_record_id=None):
        """Log a sync event to database"""
        if not self.db:
            return
        
        try:
            from models import SyncLog
            log_entry = SyncLog(
                ip_address=ip,
                action=action,
                component=component,
                message=message,
                status=status,
                sync_record_id=sync_record_id
            )
            self.db.session.add(log_entry)
            self.db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log sync event: {e}")
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of all currently blocked IPs"""
        return list(self.blocked_ips_cache)
    
    def get_sync_status(self, ip: str) -> Optional[Dict]:
        """Get status of a specific IP's sync"""
        try:
            if self.db:
                from models import BlockingSyncRecord
                record = BlockingSyncRecord.query.filter_by(ip_address=ip).order_by(
                    BlockingSyncRecord.initiated_at.desc()
                ).first()
                if record:
                    return record.to_dict()
        except Exception as e:
            logger.error(f"Failed to get sync status for {ip}: {e}")
        
        return None
    
    def health_check(self) -> Dict:
        """Check health of both systems"""
        health = {
            "timestamp": datetime.utcnow().isoformat(),
            "windows": {"status": "checking"},
            "linux": {"status": "checking"}
        }
        
        # Check Windows Firewall
        try:
            result = subprocess.run(
                "netsh advfirewall show allprofiles",
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            health["windows"]["status"] = "healthy" if result.returncode == 0 else "unhealthy"
            health["windows"]["firewall_accessible"] = result.returncode == 0
        except Exception as e:
            health["windows"]["status"] = "error"
            health["windows"]["error"] = str(e)
        
        # Check Linux API
        try:
            url = f"http://{self.linux_api_host}:{self.linux_api_port}/api/health"
            response = requests.get(url, timeout=5)
            health["linux"]["status"] = "healthy" if response.status_code == 200 else "unhealthy"
            health["linux"]["api_accessible"] = response.status_code == 200
        except Exception as e:
            health["linux"]["status"] = "error"
            health["linux"]["error"] = str(e)
        
        overall_healthy = (
            health["windows"]["status"] == "healthy" and 
            health["linux"]["status"] == "healthy"
        )
        health["overall"] = "healthy" if overall_healthy else "degraded"
        
        logger.info(f"Health check result: {health['overall']}")
        return health


# Instantiate the service
blocking_sync_service = BlockingSyncService()
