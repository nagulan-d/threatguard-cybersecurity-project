"""
IP Blocking Module for ThreatGuard
Handles IP-based access control using:
- Windows: netsh (Windows Firewall)
- Linux: iptables or ufw (Ubuntu/Debian)
- WSL: iptables
"""

import subprocess
import os
import json
import logging
import platform
from typing import List, Dict, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class IPBlocker:
    """Manages IP blocking through OS-level firewall rules"""
    
    def __init__(self, rules_file: str = "blocked_ips.json"):
        """Initialize IP blocker with persistence file"""
        self.rules_file = rules_file
        self.blocked_ips: List[str] = []
        self.whitelist_ips: List[str] = []
        self.os_type = self._detect_os_type()
        self.is_linux = self.os_type in ['linux', 'wsl']
        self.is_windows = self.os_type == 'windows'
        self.load_rules()
        logger.info(f"IP Blocker initialized. OS: {self.os_type}, Linux: {self.is_linux}, Windows: {self.is_windows}")
    
    def _detect_os_type(self) -> str:
        """Detect operating system type"""
        system = platform.system()
        
        if system == "Windows":
            return "windows"
        elif system == "Linux":
            # Check if it's WSL
            try:
                with open("/proc/version", "r") as f:
                    content = f.read().lower()
                    if "microsoft" in content or "wsl" in content:
                        return "wsl"
            except:
                pass
            return "linux"
        else:
            return "unknown"
    
    def _check_linux_system(self) -> bool:
        """Check if running on Linux/WSL where iptables is available"""
        try:
            result = subprocess.run(
                ["uname", "-s"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def load_rules(self) -> None:
        """Load blocked IPs from persistent storage"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = data.get('blocked_ips', [])
                    self.whitelist_ips = data.get('whitelist_ips', [])
                logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
            except Exception as e:
                logger.warning(f"Failed to load rules: {e}")
    
    def save_rules(self) -> None:
        """Persist blocked IPs to file"""
        try:
            with open(self.rules_file, 'w') as f:
                json.dump({
                    'blocked_ips': self.blocked_ips,
                    'whitelist_ips': self.whitelist_ips
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save rules: {e}")
    
    def block_ip(self, ip: str, reason: str = "Security threat") -> Tuple[bool, str]:
        """Block an IP address using OS-level firewall rules"""
        if ip in self.blocked_ips:
            return False, f"IP {ip} already blocked"
        
        if ip in self.whitelist_ips:
            return False, f"IP {ip} is whitelisted"
        
        # Validate IP format
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP format: {ip}"
        
        # Try OS-specific blocking
        if self.is_windows:
            success, msg = self._block_ip_windows(ip)
            if success:
                self.blocked_ips.append(ip)
                self.save_rules()
                logger.info(f"Blocked IP {ip} via Windows Firewall: {reason}")
                return True, f"IP {ip} blocked successfully via Windows Firewall"
            else:
                logger.error(f"Windows blocking failed for {ip}: {msg}")
                # DO NOT FALL BACK - return failure
                return False, f"Windows Firewall blocking failed: {msg}"
        
        elif self.is_linux:
            success, msg = self._block_ip_iptables(ip)
            if success:
                self.blocked_ips.append(ip)
                self.save_rules()
                logger.info(f"Blocked IP {ip} via iptables: {reason}")
                return True, f"IP {ip} blocked successfully via iptables"
            else:
                logger.warning(f"Linux blocking failed for {ip}: {msg}")
        
        # Fallback to application-level blocking
        self.blocked_ips.append(ip)
        self.save_rules()
        logger.info(f"Blocked IP {ip} at application level: {reason}")
        return True, f"IP {ip} blocked successfully (application-level)"
    
    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return False, f"IP {ip} not in blocked list"
        
        # Try OS-specific unblocking
        if self.is_windows:
            success, msg = self._unblock_ip_windows(ip)
            if success:
                self.blocked_ips.remove(ip)
                self.save_rules()
                logger.info(f"Unblocked IP {ip} via Windows Firewall")
                return True, f"IP {ip} unblocked successfully"
        
        elif self.is_linux:
            success, msg = self._unblock_ip_iptables(ip)
            if success:
                self.blocked_ips.remove(ip)
                self.save_rules()
                logger.info(f"Unblocked IP {ip} via iptables")
                return True, f"IP {ip} unblocked successfully"
        
        # Fallback: remove from application-level rules
        self.blocked_ips.remove(ip)
        self.save_rules()
        logger.info(f"Unblocked IP {ip} at application level")
        return True, f"IP {ip} unblocked successfully"
    
    def whitelist_ip(self, ip: str) -> Tuple[bool, str]:
        """Whitelist an IP to bypass blocking"""
        if ip in self.whitelist_ips:
            return False, f"IP {ip} already whitelisted"
        
        if not self._is_valid_ip(ip):
            return False, f"Invalid IP format: {ip}"
        
        self.whitelist_ips.append(ip)
        self.save_rules()
        logger.info(f"Whitelisted IP {ip}")
        return True, f"IP {ip} whitelisted successfully"
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        return ip in self.blocked_ips and ip not in self.whitelist_ips
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of all blocked IPs"""
        return self.blocked_ips.copy()
    
    def get_whitelist(self) -> List[str]:
        """Get list of all whitelisted IPs"""
        return self.whitelist_ips.copy()
    
    def _block_ip_windows(self, ip: str) -> Tuple[bool, str]:
        """Block IP using Windows Firewall (netsh command)"""
        try:
            # Create inbound block rule
            rule_name = f"ThreatGuard Block: {ip}"
            
            cmd = (
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip} enable=yes'
            )
            
            print(f"\n[IP_BLOCKER] Executing netsh command: {cmd}")
            logger.info(f"Executing netsh command: {cmd}")
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            stdout_text = result.stdout.decode() if result.stdout else ""
            stderr_text = result.stderr.decode() if result.stderr else ""
            
            print(f"[IP_BLOCKER] netsh result - returncode: {result.returncode}")
            print(f"[IP_BLOCKER] stdout: {stdout_text.strip()}")
            print(f"[IP_BLOCKER] stderr: {stderr_text.strip()}")
            logger.info(f"netsh result - returncode: {result.returncode}, stdout: {stdout_text.strip()}, stderr: {stderr_text.strip()}")
            
            # Check both stdout and stderr for "Ok"
            if result.returncode == 0 or "Ok" in stdout_text or "Ok" in stderr_text:
                print(f"[IP_BLOCKER] ✓ Inbound rule SUCCESS - creating outbound rule...")
                # Also create outbound block rule
                cmd_out = (
                    f'netsh advfirewall firewall add rule name="{rule_name} (Outbound)" '
                    f'dir=out action=block remoteip={ip} enable=yes'
                )
                logger.info(f"Executing outbound rule: {cmd_out}")
                subprocess.run(
                    cmd_out,
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                print(f"[IP_BLOCKER] ✓✓ BOTH RULES CREATED for {ip}")
                return True, "Windows Firewall rule added"
            else:
                error_msg = stderr_text if stderr_text else stdout_text
                print(f"[IP_BLOCKER] ✗ netsh FAILED for {ip}: {error_msg}")
                logger.error(f"netsh FAILED for {ip}: {error_msg}")
                return False, f"netsh error: {error_msg}"
        except Exception as e:
            print(f"[IP_BLOCKER] ✗✗ Exception in _block_ip_windows for {ip}: {e}")
            logger.error(f"Exception in _block_ip_windows for {ip}: {e}")
            return False, str(e)
    
    def _unblock_ip_windows(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using Windows Firewall (netsh command)"""
        try:
            rule_name = f"ThreatGuard Block: {ip}"
            
            # Remove inbound rule
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            # Remove outbound rule
            cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name} (Outbound)"'
            subprocess.run(
                cmd_out,
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            return True, "Windows Firewall rules removed"
        except Exception as e:
            return False, str(e)
    
    def _block_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Block IP using iptables command"""
        try:
            # Drop incoming traffic from IP
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Also drop output to prevent any communication
                subprocess.run(
                    f"sudo iptables -A OUTPUT -d {ip} -j DROP",
                    shell=True,
                    capture_output=True,
                    timeout=5
                )
                return True, "iptables rule added"
            else:
                return False, result.stderr.decode() if result.stderr else "iptables error"
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_iptables(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP using iptables command"""
        try:
            cmd_in = f"sudo iptables -D INPUT -s {ip} -j DROP"
            cmd_out = f"sudo iptables -D OUTPUT -d {ip} -j DROP"
            
            subprocess.run(cmd_in, shell=True, capture_output=True, timeout=5)
            subprocess.run(cmd_out, shell=True, capture_output=True, timeout=5)
            return True, "iptables rules removed"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format (IPv4/IPv6)"""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        
        return re.match(ipv6_pattern, ip) is not None
    
    def flush_rules(self) -> Tuple[bool, str]:
        """Clear all iptables rules (use with caution)"""
        if not self.is_linux:
            return False, "flush_rules only works on Linux/WSL"
        
        try:
            subprocess.run(
                "sudo iptables -F",
                shell=True,
                capture_output=True,
                timeout=5
            )
            logger.warning("All iptables rules flushed")
            return True, "Rules flushed"
        except Exception as e:
            return False, str(e)


# Global IP blocker instance
ip_blocker = IPBlocker()
