"""
IP Blocking Rules Validator and Duplicate Prevention
Ensures consistency between Windows Firewall and Linux iptables
Prevents duplicate rules and validates blocking policies
"""

import logging
import re
import subprocess
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class IPValidator:
    """Validates IP addresses"""
    
    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Validate IPv4 address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        try:
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """Validate IPv6 address"""
        # Comprehensive IPv6 validation
        pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' \
                  r'([0-9a-fA-F]{1,4}:){1,7}:|' \
                  r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' \
                  r'::1|::)$'
        return bool(re.match(pattern, ip))
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address (IPv4 or IPv6)"""
        return IPValidator.is_valid_ipv4(ip) or IPValidator.is_valid_ipv6(ip)
    
    @staticmethod
    def is_reserved_ip(ip: str) -> bool:
        """Check if IP is in reserved/private range"""
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
            ("127.0.0.0", "127.255.255.255"),
            ("169.254.0.0", "169.254.255.255"),
        ]
        
        if not IPValidator.is_valid_ipv4(ip):
            return False
        
        ip_int = IPValidator._ip_to_int(ip)
        
        for start, end in private_ranges:
            start_int = IPValidator._ip_to_int(start)
            end_int = IPValidator._ip_to_int(end)
            
            if start_int <= ip_int <= end_int:
                return True
        
        return False
    
    @staticmethod
    def _ip_to_int(ip: str) -> int:
        """Convert IP address to integer"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])


class DuplicatePrevention:
    """Prevents duplicate firewall rules"""
    
    def __init__(self):
        self.seen_rules: Dict[str, Dict] = {}  # ip -> rule_info
    
    def register_rule(self, ip: str, system: str, rule_name: str = None) -> bool:
        """
        Register a rule to prevent duplicates
        
        Args:
            ip: IP address
            system: System where rule is created ('windows' or 'linux')
            rule_name: Optional rule name/identifier
            
        Returns:
            True if rule is new, False if it's a duplicate
        """
        if ip not in self.seen_rules:
            self.seen_rules[ip] = {}
        
        if system in self.seen_rules[ip]:
            logger.warning(f"Duplicate rule detected for {ip} on {system}")
            return False
        
        self.seen_rules[ip][system] = {
            "rule_name": rule_name or f"TG_BLOCK_{ip.replace('.', '_')}",
            "created_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Rule registered for {ip} on {system}")
        return True
    
    def is_rule_duplicate(self, ip: str, system: str) -> bool:
        """Check if rule already exists"""
        return ip in self.seen_rules and system in self.seen_rules[ip]
    
    def get_rule_status(self, ip: str) -> Dict:
        """Get rule status for an IP"""
        if ip not in self.seen_rules:
            return {"ip": ip, "status": "not_blocked"}
        
        return {
            "ip": ip,
            "status": "blocked",
            "systems": self.seen_rules[ip]
        }
    
    def clear_rule(self, ip: str, system: str = None) -> bool:
        """Clear rule(s) for an IP"""
        if ip not in self.seen_rules:
            return False
        
        if system:
            if system in self.seen_rules[ip]:
                del self.seen_rules[ip][system]
                logger.info(f"Rule cleared for {ip} on {system}")
        else:
            del self.seen_rules[ip]
            logger.info(f"All rules cleared for {ip}")
        
        return True


class WindowsRuleValidator:
    """Validates Windows Firewall rules"""
    
    @staticmethod
    def verify_rule_exists(ip: str) -> Tuple[bool, str]:
        """Verify that Windows Firewall rule exists for an IP"""
        try:
            rule_name_in = f"TG_BLOCK_{ip.replace('.', '_')}_IN"
            rule_name_out = f"TG_BLOCK_{ip.replace('.', '_')}_OUT"
            
            cmd = f'netsh advfirewall firewall show rule name="{rule_name_in}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if "Rule Name:" in result.stdout:
                return True, f"Rule {rule_name_in} exists"
            
            return False, f"Rule {rule_name_in} not found"
        
        except Exception as e:
            logger.error(f"Error verifying Windows rule for {ip}: {e}")
            return False, str(e)
    
    @staticmethod
    def get_all_threatguard_rules() -> List[Dict]:
        """Get all ThreatGuard blocking rules"""
        try:
            cmd = 'netsh advfirewall firewall show rule name="TG_BLOCK*"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            rules = []
            current_rule = {}
            
            for line in result.stdout.split('\n'):
                if "Rule Name:" in line:
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif "Direction:" in line and current_rule:
                    current_rule["direction"] = line.split(":", 1)[1].strip()
                elif "Action:" in line and current_rule:
                    current_rule["action"] = line.split(":", 1)[1].strip()
                elif "RemoteIP:" in line and current_rule:
                    current_rule["remote_ip"] = line.split(":", 1)[1].strip()
            
            if current_rule:
                rules.append(current_rule)
            
            return rules
        
        except Exception as e:
            logger.error(f"Error getting Windows rules: {e}")
            return []
    
    @staticmethod
    def clean_duplicate_rules(ip: str) -> Tuple[int, str]:
        """Remove duplicate rules for an IP"""
        try:
            rules = WindowsRuleValidator.get_all_threatguard_rules()
            
            duplicate_count = 0
            for rule in rules:
                if ip in rule.get("remote_ip", ""):
                    rule_name = rule.get("name", "")
                    
                    # Keep only the first occurrence
                    if duplicate_count > 0:
                        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                        subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                        duplicate_count += 1
                        logger.info(f"Removed duplicate rule: {rule_name}")
            
            return duplicate_count, f"Removed {duplicate_count} duplicate rules"
        
        except Exception as e:
            logger.error(f"Error cleaning duplicate rules: {e}")
            return 0, str(e)


class LinuxRuleValidator:
    """Validates Linux iptables rules"""
    
    @staticmethod
    def verify_rule_exists(ip: str) -> Tuple[bool, str]:
        """Verify that iptables rule exists for an IP"""
        try:
            # Check for inbound rule
            cmd = f"sudo iptables -C THREATGUARD -s {ip} -j DROP"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return True, f"Rule for {ip} exists"
            
            return False, f"Rule for {ip} not found"
        
        except Exception as e:
            logger.error(f"Error verifying Linux rule for {ip}: {e}")
            return False, str(e)
    
    @staticmethod
    def get_blocked_ips() -> List[str]:
        """Get list of blocked IPs from iptables"""
        try:
            cmd = "sudo iptables -L THREATGUARD -n"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            blocked_ips = []
            
            for line in result.stdout.split('\n'):
                # Parse iptables output
                parts = line.strip().split()
                if len(parts) > 3 and parts[0] == 'DROP':
                    # Extract IP from "DROP all -- <ip> anywhere"
                    if len(parts) > 4:
                        ip = parts[4]
                        if IPValidator.is_valid_ip(ip):
                            blocked_ips.append(ip)
            
            return list(set(blocked_ips))  # Remove duplicates
        
        except Exception as e:
            logger.error(f"Error getting blocked IPs from iptables: {e}")
            return []
    
    @staticmethod
    def clean_duplicate_rules(ip: str) -> Tuple[int, str]:
        """Remove duplicate iptables rules for an IP"""
        try:
            duplicate_count = 0
            
            # Remove all inbound rules and re-add once
            remove_cmd = f"sudo iptables -D THREATGUARD -s {ip} -j DROP"
            
            while True:
                result = subprocess.run(
                    remove_cmd,
                    shell=True,
                    capture_output=True,
                    timeout=5
                )
                
                if result.returncode != 0:
                    break
                
                duplicate_count += 1
            
            # Re-add rule once
            if duplicate_count > 0:
                add_cmd = f"sudo iptables -I THREATGUARD -s {ip} -j DROP"
                subprocess.run(add_cmd, shell=True, capture_output=True, timeout=5)
                logger.info(f"Removed {duplicate_count} duplicate iptables rules for {ip}")
            
            return duplicate_count, f"Removed {duplicate_count} duplicate rules"
        
        except Exception as e:
            logger.error(f"Error cleaning duplicate Linux rules: {e}")
            return 0, str(e)


class SyncConsistencyValidator:
    """Validates consistency between Windows and Linux blocking"""
    
    def __init__(self):
        self.validation_log: List[Dict] = []
    
    def validate_sync(self, ip: str) -> Dict:
        """
        Validate that an IP is blocked on both systems
        
        Returns:
            Validation result
        """
        result = {
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "windows": None,
            "linux": None,
            "consistent": False,
            "issues": []
        }
        
        # Check Windows
        windows_exists, win_msg = WindowsRuleValidator.verify_rule_exists(ip)
        result["windows"] = {
            "exists": windows_exists,
            "message": win_msg
        }
        
        # Check Linux
        linux_exists, linux_msg = LinuxRuleValidator.verify_rule_exists(ip)
        result["linux"] = {
            "exists": linux_exists,
            "message": linux_msg
        }
        
        # Check consistency
        if windows_exists and linux_exists:
            result["consistent"] = True
        elif not windows_exists and not linux_exists:
            result["consistent"] = True
        else:
            result["consistent"] = False
            result["issues"].append("Blocking status inconsistent across systems")
        
        # Check for duplicates
        if windows_exists:
            win_dupes, win_dupe_msg = WindowsRuleValidator.clean_duplicate_rules(ip)
            if win_dupes > 0:
                result["issues"].append(f"Windows: {win_dupe_msg}")
        
        if linux_exists:
            linux_dupes, linux_dupe_msg = LinuxRuleValidator.clean_duplicate_rules(ip)
            if linux_dupes > 0:
                result["issues"].append(f"Linux: {linux_dupe_msg}")
        
        self.validation_log.append(result)
        
        if result["issues"]:
            logger.warning(f"Validation issues for {ip}: {result['issues']}")
        else:
            logger.info(f"Validation passed for {ip}")
        
        return result
    
    def validate_all_blocks(self) -> Dict:
        """Validate all blocked IPs"""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "validations": [],
            "total": 0,
            "consistent": 0,
            "inconsistent": 0,
            "issues_found": 0
        }
        
        # Get blocked IPs from Windows
        windows_rules = WindowsRuleValidator.get_all_threatguard_rules()
        windows_ips = set()
        
        for rule in windows_rules:
            remote_ip = rule.get("remote_ip", "")
            if IPValidator.is_valid_ip(remote_ip):
                windows_ips.add(remote_ip)
        
        # Validate all Windows IPs
        for ip in windows_ips:
            validation = self.validate_sync(ip)
            results["validations"].append(validation)
            results["total"] += 1
            
            if validation["consistent"]:
                results["consistent"] += 1
            else:
                results["inconsistent"] += 1
            
            if validation["issues"]:
                results["issues_found"] += len(validation["issues"])
        
        return results
    
    def get_validation_history(self, limit: int = 20) -> List[Dict]:
        """Get validation history"""
        return self.validation_log[-limit:]


# Global instances
duplicate_prevention = DuplicatePrevention()
sync_validator = SyncConsistencyValidator()
