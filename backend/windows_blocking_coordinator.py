"""
Windows Blocking Coordinator
Bridges the Flask application with the blocking sync service
Handles IP blocking requests from admin dashboard and threat processor
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from functools import wraps
import jwt

logger = logging.getLogger(__name__)


class WindowsBlockingCoordinator:
    """Coordinates IP blocking actions initiated from Windows/Admin Dashboard"""
    
    def __init__(self, sync_service=None, db=None, app=None):
        """Initialize the Windows blocking coordinator"""
        self.sync_service = sync_service
        self.db = db
        self.app = app
        self.admin_token_secret = os.getenv("ADMIN_TOKEN_SECRET", "admin_secret")
        logger.info("WindowsBlockingCoordinator initialized")
    
    def block_threat_ip(self, ip_address: str, threat_info: dict, 
                       user=None, allow_partial_block: bool = False) -> Dict:
        """
        Block an IP address from detected threat
        
        Args:
            ip_address: IP to block
            threat_info: Dictionary with threat details (category, risk_score, etc.)
            user: User initiating the block
            allow_partial_block: Allow blocking if one system fails
            
        Returns:
            Result dictionary with blocking status
        """
        logger.info(f"🔒 Initiating threat blocking for IP {ip_address}")
        
        # Validate IP address
        if not self._is_valid_ip(ip_address):
            logger.error(f"Invalid IP address: {ip_address}")
            return {
                "success": False,
                "ip": ip_address,
                "error": "Invalid IP address format",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Prepare threat data
        blocking_context = {
            "category": threat_info.get("category", "Unknown"),
            "risk_score": threat_info.get("risk_score", 0),
            "reason": threat_info.get("reason", "Security threat detected"),
            "threat_type": threat_info.get("threat_type", "Unknown"),
            "allow_partial_block": allow_partial_block,
            "initiated_by": user.username if user else "system"
        }
        
        # Execute synchronized blocking
        if self.sync_service:
            sync_result = self.sync_service.block_ip_synchronized(
                ip=ip_address,
                threat_data=blocking_context,
                user=user
            )
            
            # Update database records if available
            if self.db and user:
                self._record_blocking_action(
                    ip_address=ip_address,
                    action="block",
                    threat_info=threat_info,
                    sync_result=sync_result,
                    user=user
                )
            
            return sync_result
        else:
            logger.error("Sync service not available")
            return {
                "success": False,
                "ip": ip_address,
                "error": "Blocking service unavailable",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def unblock_threat_ip(self, ip_address: str, user=None) -> Dict:
        """
        Unblock a previously blocked IP
        
        Args:
            ip_address: IP to unblock
            user: User initiating the unblock
            
        Returns:
            Result dictionary with unblocking status
        """
        logger.info(f"🔓 Initiating threat unblocking for IP {ip_address}")
        
        if not self._is_valid_ip(ip_address):
            logger.error(f"Invalid IP address: {ip_address}")
            return {
                "success": False,
                "ip": ip_address,
                "error": "Invalid IP address format",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        if self.sync_service:
            sync_result = self.sync_service.unblock_ip_synchronized(
                ip=ip_address,
                user=user
            )
            
            # Update database records
            if self.db and user:
                self._record_blocking_action(
                    ip_address=ip_address,
                    action="unblock",
                    sync_result=sync_result,
                    user=user
                )
            
            return sync_result
        else:
            logger.error("Sync service not available")
            return {
                "success": False,
                "ip": ip_address,
                "error": "Blocking service unavailable",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def auto_block_high_risk_threat(self, ip_address: str, threat_info: dict) -> Dict:
        """
        Automatically block high-risk threats (no user confirmation needed)
        
        Args:
            ip_address: IP to block
            threat_info: Threat details
            
        Returns:
            Blocking result
        """
        logger.warning(f"⚠️ AUTO-BLOCKING high-risk threat: {ip_address} (Score: {threat_info.get('risk_score', 0)})")
        
        # Auto-block with partial blocking allowed (for resilience)
        return self.block_threat_ip(
            ip_address=ip_address,
            threat_info=threat_info,
            user=None,
            allow_partial_block=True
        )
    
    def get_blocked_ips_list(self) -> List[Dict]:
        """Get list of all currently blocked IPs with details"""
        if not self.db:
            return []
        
        try:
            from models import BlockingSyncRecord
            
            # Get all active (completed) blocking records
            active_blocks = BlockingSyncRecord.query.filter(
                BlockingSyncRecord.action == "block",
                BlockingSyncRecord.sync_status == "completed"
            ).order_by(BlockingSyncRecord.initiated_at.desc()).all()
            
            blocked_ips = []
            for record in active_blocks:
                blocked_ips.append({
                    "ip": record.ip_address,
                    "threat_category": record.threat_category,
                    "risk_score": record.risk_score,
                    "reason": record.reason,
                    "blocked_at": record.initiated_at.isoformat() if record.initiated_at else None,
                    "windows_status": record.windows_status,
                    "linux_status": record.linux_status,
                    "blocked_by": record.initiator.username if record.initiator else "system"
                })
            
            return blocked_ips
        
        except Exception as e:
            logger.error(f"Failed to retrieve blocked IPs list: {e}")
            return []
    
    def get_blocking_history(self, ip_address: str, limit: int = 10) -> List[Dict]:
        """Get blocking/unblocking history for an IP"""
        if not self.db:
            return []
        
        try:
            from models import BlockingSyncRecord
            
            history = BlockingSyncRecord.query.filter_by(
                ip_address=ip_address
            ).order_by(
                BlockingSyncRecord.initiated_at.desc()
            ).limit(limit).all()
            
            return [record.to_dict() for record in history]
        
        except Exception as e:
            logger.error(f"Failed to retrieve blocking history for {ip_address}: {e}")
            return []
    
    def get_system_health(self) -> Dict:
        """Get health status of both blocking systems"""
        if not self.sync_service:
            return {"status": "error", "message": "Sync service unavailable"}
        
        return self.sync_service.health_check()
    
    def retry_failed_sync(self, sync_record_id: int) -> Dict:
        """Retry a failed blocking synchronization"""
        if not self.db:
            return {"success": False, "error": "Database not available"}
        
        try:
            from models import BlockingSyncRecord
            
            sync_record = BlockingSyncRecord.query.get(sync_record_id)
            if not sync_record:
                return {"success": False, "error": f"Sync record {sync_record_id} not found"}
            
            logger.info(f"Retrying sync for IP {sync_record.ip_address}")
            
            if sync_record.action == "block":
                result = self.block_threat_ip(
                    ip_address=sync_record.ip_address,
                    threat_info={
                        "category": sync_record.threat_category,
                        "risk_score": sync_record.risk_score,
                        "reason": sync_record.reason
                    }
                )
            else:
                result = self.unblock_threat_ip(ip_address=sync_record.ip_address)
            
            return {
                "success": result.get("status") in ["completed", "partial"],
                "sync_result": result
            }
        
        except Exception as e:
            logger.error(f"Exception during retry: {e}")
            return {"success": False, "error": str(e)}
    
    def _record_blocking_action(self, ip_address: str, action: str, 
                               sync_result: dict, user=None, threat_info: dict = None):
        """Record blocking action in database"""
        if not self.db:
            return
        
        try:
            from models import ThreatActionLog
            
            action_log = ThreatActionLog(
                user_id=user.id if user else None,
                action=action,
                ip_address=ip_address,
                performed_by_user_id=user.id if user else None,
                details=str({
                    "windows_status": sync_result.get("windows_status"),
                    "linux_status": sync_result.get("linux_status"),
                    "sync_status": sync_result.get("status"),
                    "threat_category": threat_info.get("category") if threat_info else None
                })
            )
            
            self.db.session.add(action_log)
            self.db.session.commit()
            logger.debug(f"Recorded blocking action: {action} for {ip_address}")
        
        except Exception as e:
            logger.warning(f"Failed to record blocking action: {e}")
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)"""
        import re
        
        # IPv4 validation
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip_str):
            parts = ip_str.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # IPv6 validation (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv6_pattern, ip_str))
    
    def get_sync_statistics(self) -> Dict:
        """Get synchronization statistics"""
        if not self.db:
            return {}
        
        try:
            from models import BlockingSyncRecord
            from sqlalchemy import func
            
            total_blocks = BlockingSyncRecord.query.filter_by(
                action="block"
            ).count()
            
            completed_blocks = BlockingSyncRecord.query.filter(
                BlockingSyncRecord.action == "block",
                BlockingSyncRecord.sync_status == "completed"
            ).count()
            
            failed_blocks = BlockingSyncRecord.query.filter(
                BlockingSyncRecord.action == "block",
                BlockingSyncRecord.sync_status == "failed"
            ).count()
            
            partial_blocks = BlockingSyncRecord.query.filter(
                BlockingSyncRecord.action == "block",
                BlockingSyncRecord.sync_status == "partial"
            ).count()
            
            avg_risk_score = self.db.session.query(
                func.avg(BlockingSyncRecord.risk_score)
            ).filter(
                BlockingSyncRecord.action == "block"
            ).scalar() or 0
            
            return {
                "total_blocks": total_blocks,
                "completed": completed_blocks,
                "failed": failed_blocks,
                "partial": partial_blocks,
                "success_rate": round(completed_blocks / total_blocks * 100, 2) if total_blocks > 0 else 0,
                "average_risk_score": round(avg_risk_score, 2),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get sync statistics: {e}")
            return {}


# Instantiate the coordinator
coordinator = WindowsBlockingCoordinator()
