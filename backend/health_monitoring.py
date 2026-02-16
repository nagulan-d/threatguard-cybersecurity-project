"""
Health Check and Monitoring Service for IP Blocking Synchronization
Continuously monitors Windows Firewall and Linux iptables health
Provides metrics and alerts for sync issues
"""

import logging
import subprocess
import threading
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum
import json

logger = logging.getLogger(__name__)


class SystemHealth(Enum):
    """System health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class HealthCheckMetrics:
    """Stores health metrics"""
    
    def __init__(self):
        self.checks: List[Dict] = []
        self.max_history = 100
    
    def add_check(self, system: str, timestamp: datetime, status: str, details: Dict = None):
        """Add a health check result"""
        check = {
            "system": system,
            "timestamp": timestamp.isoformat(),
            "status": status,
            "details": details or {}
        }
        self.checks.append(check)
        
        # Trim history
        if len(self.checks) > self.max_history:
            self.checks = self.checks[-self.max_history:]
    
    def get_recent_checks(self, system: str = None, limit: int = 10) -> List[Dict]:
        """Get recent health checks"""
        if system:
            filtered = [c for c in self.checks if c["system"] == system]
            return filtered[-limit:]
        return self.checks[-limit:]
    
    def get_statistics(self, system: str = None) -> Dict:
        """Get health statistics"""
        checks = [c for c in self.checks if c["system"] == system] if system else self.checks
        
        if not checks:
            return {"total": 0, "healthy": 0, "degraded": 0, "unhealthy": 0}
        
        total = len(checks)
        healthy = len([c for c in checks if c["status"] == "healthy"])
        degraded = len([c for c in checks if c["status"] == "degraded"])
        unhealthy = len([c for c in checks if c["status"] == "unhealthy"])
        
        return {
            "total": total,
            "healthy": healthy,
            "degraded": degraded,
            "unhealthy": unhealthy,
            "healthy_percentage": (healthy / total * 100) if total > 0 else 0
        }


class WindowsFirewallHealthCheck:
    """Checks health of Windows Firewall"""
    
    def __init__(self):
        self.last_check_time = None
        self.last_status = None
        self.rule_count = 0
    
    def check(self) -> Dict:
        """Perform health check on Windows Firewall"""
        result = {
            "timestamp": datetime.utcnow(),
            "status": SystemHealth.UNKNOWN.value,
            "details": {}
        }
        
        try:
            # Check if firewall is running
            response = subprocess.run(
                "netsh advfirewall show allprofiles",
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if response.returncode != 0:
                result["status"] = SystemHealth.UNHEALTHY.value
                result["details"]["error"] = "Firewall not accessible"
                return result
            
            # Parse output
            output = response.stdout.lower()
            profiles_active = {}
            
            for profile in ["domain", "private", "public"]:
                if f"{profile} profile" in output:
                    if "state on" in output:
                        profiles_active[profile] = "on"
                    else:
                        profiles_active[profile] = "off"
            
            # Count ThreatGuard rules
            rules_response = subprocess.run(
                'netsh advfirewall firewall show rule name="TG_BLOCK*" | find /c "Rule Name"',
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            try:
                rule_count = int(rules_response.stdout.strip()) if rules_response.stdout.strip() else 0
            except ValueError:
                rule_count = 0
            
            self.rule_count = rule_count
            
            result["status"] = SystemHealth.HEALTHY.value
            result["details"] = {
                "profiles": profiles_active,
                "active_blocking_rules": rule_count,
                "message": "Windows Firewall healthy"
            }
        
        except subprocess.TimeoutExpired:
            result["status"] = SystemHealth.DEGRADED.value
            result["details"]["error"] = "Firewall check timeout"
        
        except Exception as e:
            result["status"] = SystemHealth.UNHEALTHY.value
            result["details"]["error"] = str(e)
        
        self.last_check_time = result["timestamp"]
        self.last_status = result["status"]
        
        return result


class LinuxAgentHealthCheck:
    """Checks health of Linux blocking agent"""
    
    def __init__(self, api_host: str = "192.168.1.100", api_port: int = 5001, api_token: str = ""):
        self.api_host = api_host
        self.api_port = api_port
        self.api_token = api_token
        self.last_check_time = None
        self.last_status = None
        self.blocked_ip_count = 0
        self.response_time = 0
    
    def set_connection_info(self, host: str, port: int, token: str = ""):
        """Update connection information"""
        self.api_host = host
        self.api_port = port
        self.api_token = token
    
    def check(self) -> Dict:
        """Perform health check on Linux agent"""
        result = {
            "timestamp": datetime.utcnow(),
            "status": SystemHealth.UNKNOWN.value,
            "details": {}
        }
        
        try:
            url = f"http://{self.api_host}:{self.api_port}/api/health"
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            
            start_time = time.time()
            response = requests.get(
                url,
                headers=headers,
                timeout=5
            )
            response_time = time.time() - start_time
            self.response_time = response_time
            
            if response.status_code == 200:
                data = response.json()
                blocked_count = data.get("blocked_ips_count", 0)
                self.blocked_ip_count = blocked_count
                
                result["status"] = SystemHealth.HEALTHY.value
                result["details"] = {
                    "service": data.get("service", "Unknown"),
                    "blocked_ips_count": blocked_count,
                    "response_time_seconds": round(response_time, 3),
                    "message": "Linux agent is healthy"
                }
            else:
                result["status"] = SystemHealth.DEGRADED.value
                result["details"]["error"] = f"HTTP {response.status_code}"
        
        except requests.exceptions.Timeout:
            result["status"] = SystemHealth.DEGRADED.value
            result["details"]["error"] = "Request timeout"
        
        except requests.exceptions.ConnectionError:
            result["status"] = SystemHealth.UNHEALTHY.value
            result["details"]["error"] = f"Cannot connect to {self.api_host}:{self.api_port}"
        
        except Exception as e:
            result["status"] = SystemHealth.UNHEALTHY.value
            result["details"]["error"] = str(e)
        
        self.last_check_time = result["timestamp"]
        self.last_status = result["status"]
        
        return result


class HealthCheckService:
    """Main service for monitoring system health"""
    
    def __init__(self, check_interval: int = 60, auto_start: bool = True):
        """
        Initialize health check service
        
        Args:
            check_interval: Seconds between health checks
            auto_start: Start monitoring thread automatically
        """
        self.check_interval = check_interval
        self.running = False
        self.monitor_thread = None
        
        # Initialize checkers
        self.windows_checker = WindowsFirewallHealthCheck()
        self.linux_checker = LinuxAgentHealthCheck()
        
        # Metrics tracking
        self.metrics = HealthCheckMetrics()
        
        # Overall health state
        self.overall_health = SystemHealth.UNKNOWN.value
        self.last_overall_check = None
        
        # Alert callbacks
        self.alert_callbacks: List[callable] = []
        
        if auto_start:
            self.start()
        
        logger.info(f"HealthCheckService initialized (interval: {check_interval}s)")
    
    def start(self):
        """Start monitoring thread"""
        if self.running:
            logger.warning("Health check service already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Health check service started")
    
    def stop(self):
        """Stop monitoring thread"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Health check service stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.check_all_systems()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in health check loop: {e}", exc_info=True)
                time.sleep(5)
    
    def check_all_systems(self) -> Dict:
        """Check health of all systems"""
        checks = {
            "timestamp": datetime.utcnow().isoformat(),
            "windows": None,
            "linux": None,
            "overall": SystemHealth.UNKNOWN.value
        }
        
        # Windows check
        windows_result = self.windows_checker.check()
        checks["windows"] = windows_result
        self.metrics.add_check("windows", windows_result["timestamp"], windows_result["status"], 
                              windows_result["details"])
        
        # Linux check
        linux_result = self.linux_checker.check()
        checks["linux"] = linux_result
        self.metrics.add_check("linux", linux_result["timestamp"], linux_result["status"],
                              linux_result["details"])
        
        # Determine overall health
        statuses = [windows_result["status"], linux_result["status"]]
        
        if all(s == SystemHealth.HEALTHY.value for s in statuses):
            checks["overall"] = SystemHealth.HEALTHY.value
        elif any(s == SystemHealth.UNHEALTHY.value for s in statuses):
            checks["overall"] = SystemHealth.UNHEALTHY.value
        else:
            checks["overall"] = SystemHealth.DEGRADED.value
        
        self.overall_health = checks["overall"]
        self.last_overall_check = datetime.utcnow()
        
        # Check for degradation and trigger alerts
        if checks["overall"] != SystemHealth.HEALTHY.value:
            self._trigger_alert(checks)
        
        logger.debug(f"Health check complete: {checks['overall']}")
        return checks
    
    def _trigger_alert(self, health_check: Dict):
        """Trigger alert callbacks"""
        for callback in self.alert_callbacks:
            try:
                threading.Thread(target=callback, args=(health_check,), daemon=True).start()
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def add_alert_callback(self, callback: callable):
        """Register an alert callback"""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: callable):
        """Unregister an alert callback"""
        try:
            self.alert_callbacks.remove(callback)
        except ValueError:
            pass
    
    def get_current_health(self) -> Dict:
        """Get current health status"""
        return {
            "overall": self.overall_health,
            "windows": {
                "status": self.windows_checker.last_status,
                "last_checked": self.windows_checker.last_check_time.isoformat() if self.windows_checker.last_check_time else None,
                "active_rules": self.windows_checker.rule_count
            },
            "linux": {
                "status": self.linux_checker.last_status,
                "last_checked": self.linux_checker.last_check_time.isoformat() if self.linux_checker.last_check_time else None,
                "blocked_ips": self.linux_checker.blocked_ip_count,
                "response_time_seconds": self.linux_checker.response_time
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_health_statistics(self) -> Dict:
        """Get health statistics"""
        return {
            "windows": self.metrics.get_statistics("windows"),
            "linux": self.metrics.get_statistics("linux"),
            "overall": self.metrics.get_statistics(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_health_history(self, system: str = None, limit: int = 20) -> List[Dict]:
        """Get health check history"""
        return self.metrics.get_recent_checks(system, limit)
    
    def get_status_report(self) -> Dict:
        """Generate comprehensive status report"""
        return {
            "current_status": self.get_current_health(),
            "statistics": self.get_health_statistics(),
            "recent_history": {
                "windows": self.get_health_history("windows", 5),
                "linux": self.get_health_history("linux", 5)
            },
            "timestamp": datetime.utcnow().isoformat()
        }


# Global service instance
health_check_service = HealthCheckService(check_interval=60, auto_start=True)
