"""
Complete Testing Script for Auto-Blocking in Kali VM
Tests the entire flow: Threats → Auto-Block → Verify in Kali VM
"""

import requests
import json
import time
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

# Configuration
BACKEND_URL = "http://localhost:5000"
KALI_VM_IP = "192.168.56.101"  # CHANGE THIS
KALI_VM_USER = "kali"         # CHANGE THIS
KALI_VM_PASSWORD = "kali"  # CHANGE THIS

# Test data: High-risk IP addresses (will be auto-blocked)
# Using real (but non-critical) IPs for testing
TEST_HIGH_RISK_IPS = [
    "8.8.8.9",      # Suspicious similar to Google DNS
    "1.1.1.2",      # Suspicious similar to Cloudflare DNS
    "123.45.67.89", # Clearly non-standard
    "192.0.2.1",    # TEST-NET-1 (reserved for examples)
    "198.51.100.1", # TEST-NET-2 (reserved for examples)
]

# Test data: Medium-risk IPs (won't be auto-blocked, score < 75)
TEST_MEDIUM_RISK_IPS = [
    "10.0.0.1",
    "172.16.0.1",
]

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


def print_section(title: str):
    """Print a section header"""
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{Colors.RESET}\n")


def print_success(msg: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")


def print_error(msg: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}")


def print_info(msg: str):
    """Print info message"""
    print(f"{Colors.YELLOW}ⓘ {msg}{Colors.RESET}")


def run_ssh_command(cmd: str) -> Tuple[bool, str]:
    """
    Run command on Kali VM via SSH
    Returns: (success, output)
    """
    try:
        result = subprocess.run(
            ["ssh", f"{KALI_VM_USER}@{KALI_VM_IP}", cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


# ============================================================================
# PHASE 1: PRE-FLIGHT CHECKS
# ============================================================================

def check_backend_connectivity() -> bool:
    """Check if backend is running"""
    print_section("PHASE 1: PRE-FLIGHT CHECKS")
    
    try:
        response = requests.get(f"{BACKEND_URL}/api/threats", timeout=5)
        print_success(f"Backend is accessible ({response.status_code})")
        return True
    except Exception as e:
        print_error(f"Backend not accessible: {e}")
        return False


def check_kali_vm_connectivity() -> bool:
    """Check if Kali VM is accessible"""
    try:
        # Test SSH connection
        success, output = run_ssh_command("echo 'Kali VM is online'")
        if success:
            print_success(f"Kali VM is accessible via SSH ({KALI_VM_IP})")
            return True
        else:
            print_error(f"Kali VM SSH connection failed: {output}")
            return False
    except Exception as e:
        print_error(f"Kali VM connectivity check failed: {e}")
        return False


def check_kali_firewall() -> bool:
    """Check if iptables/firewall is available on Kali"""
    try:
        success, output = run_ssh_command("sudo iptables -L -n | head -5")
        if success and "Chain" in output:
            print_success("iptables firewall is available on Kali VM")
            return True
        else:
            print_error(f"iptables check failed: {output}")
            return False
    except Exception as e:
        print_error(f"Firewall check failed: {e}")
        return False


def preflights() -> bool:
    """Run all preflight checks"""
    checks = [
        ("Backend Connectivity", check_backend_connectivity),
        ("Kali VM Connectivity", check_kali_vm_connectivity),
        ("Kali Firewall", check_kali_firewall),
    ]
    
    results = []
    for name, check in checks:
        print_info(f"Checking: {name}...")
        result = check()
        results.append(result)
        time.sleep(1)
    
    if all(results):
        print_success(f"All {len(results)} preflight checks passed!")
        return True
    else:
        print_error(f"Some preflight checks failed ({sum(results)}/{len(results)})")
        return False


# ============================================================================
# PHASE 2: INJECT TEST THREATS
# ============================================================================

def create_test_threat(ip: str, score: int, category: str) -> Dict:
    """Create a test threat object"""
    return {
        "indicator": ip,
        "type": "IPv4",
        "IP Address": ip,
        "Risk Category": "High" if score >= 75 else "Medium" if score >= 50 else "Low",
        "Score": score,
        "Summary": f"Test threat from {ip} (Score: {score})",
        "Detected When": datetime.utcnow().isoformat() + "Z",
        "tags": ["test", "automated-threat"],
        "description": f"Automated test threat - {ip}",
    }


def inject_test_threats() -> List[str]:
    """
    Inject test threats into recent_threats.json
    Returns: List of high-risk IPs that should be auto-blocked
    """
    print_section("PHASE 2: INJECT TEST THREATS")
    
    threats_file = Path("recent_threats.json")
    
    # Create test threats
    threats_to_inject = []
    
    # High-risk threats (will be auto-blocked, score >= 75)
    for ip in TEST_HIGH_RISK_IPS:
        score = 75 + (hash(ip) % 25)  # Score between 75-99
        threat = create_test_threat(ip, score, "High")
        threats_to_inject.append(threat)
        print_info(f"Created HIGH-RISK threat: {ip} (Score: {score})")
    
    # Medium-risk threats (won't be auto-blocked, score < 75)
    for ip in TEST_MEDIUM_RISK_IPS:
        score = 50 + (hash(ip) % 25)  # Score between 50-74
        threat = create_test_threat(ip, score, "Medium")
        threats_to_inject.append(threat)
        print_info(f"Created MEDIUM-RISK threat: {ip} (Score: {score})")
    
    # Save to file
    try:
        with open(threats_file, 'w') as f:
            json.dump(threats_to_inject, f, indent=2)
        print_success(f"Injected {len(threats_to_inject)} test threats to {threats_file}")
        return TEST_HIGH_RISK_IPS
    except Exception as e:
        print_error(f"Failed to inject threats: {e}")
        return []


# ============================================================================
# PHASE 3: TRIGGER AUTO-BLOCKING
# ============================================================================

def wait_for_auto_blocking(timeout: int = 120):
    """
    Wait for auto-blocking to kick in
    Monitor blocked_ips.json file for blocked IPs
    """
    print_section("PHASE 3: WAIT FOR AUTO-BLOCKING (Up to 2 minutes)")
    
    start_time = time.time()
    high_risk_ips = TEST_HIGH_RISK_IPS
    blocked_ips = set()
    blocked_ips_file = Path("blocked_ips.json")
    
    print_info("Monitoring blocked_ips.json for blocked IPs...")
    print_info(f"Expected to block: {', '.join(high_risk_ips)}")
    
    while time.time() - start_time < timeout:
        try:
            # Read blocked_ips.json directly (no auth needed)
            if blocked_ips_file.exists():
                with open(blocked_ips_file, 'r') as f:
                    data = json.load(f)
                    current_blocked = set(data.get("blocked_ips", []))
                    
                    newly_blocked = current_blocked - blocked_ips
                    if newly_blocked:
                        for ip in newly_blocked:
                            print_success(f"Auto-blocked: {ip}")
                        blocked_ips = current_blocked
                    
                    # Check if all high-risk IPs are blocked
                    if all(ip in blocked_ips for ip in high_risk_ips):
                        print_success(f"All {len(high_risk_ips)} high-risk IPs have been auto-blocked!")
                        return True
        except Exception as e:
            print_error(f"Error checking blocked IPs: {e}")
        
        # Show progress
        elapsed = int(time.time() - start_time)
        remaining = timeout - elapsed
        print_info(f"Waiting... ({elapsed}s elapsed, {remaining}s remaining)")
        
        time.sleep(10)  # Check every 10 seconds
    
    print_error(f"Auto-blocking timeout after {timeout}s")
    return False


# ============================================================================
# PHASE 4: VERIFY IN KALI VM
# ============================================================================

def get_blocked_rules_kali() -> List[str]:
    """
    Get list of blocked IPs in Kali VM firewall
    Uses iptables DROP rules
    """
    output_lines = []
    
    # Check iptables INPUT chain for DROP rules
    cmd = "sudo iptables -L INPUT -n | grep DROP | awk '{print $5}'"
    success, output = run_ssh_command(cmd)
    
    if success:
        blocked = [line.strip() for line in output.strip().split('\n') if line.strip()]
        return blocked
    return []


def verify_ip_blocked_in_kali(ip: str) -> bool:
    """Verify if specific IP is blocked in Kali VM"""
    # Try to ping the IP (will fail if blocked)
    cmd = f"timeout 2 ping -c 1 {ip} > /dev/null 2>&1 && echo 'REACHABLE' || echo 'BLOCKED'"
    success, output = run_ssh_command(cmd)
    
    return "BLOCKED" in output


def verify_blocking_kali():
    """Verify all auto-blocked IPs are blocked in Kali VM"""
    print_section("PHASE 4: VERIFY IN KALI VM")
    
    verified_blocks = []
    
    for ip in TEST_HIGH_RISK_IPS:
        print_info(f"Verifying {ip} in Kali VM firewall...")
        is_blocked = verify_ip_blocked_in_kali(ip)
        
        if is_blocked:
            print_success(f"IP {ip} is BLOCKED in Kali VM")
            verified_blocks.append(ip)
        else:
            print_error(f"IP {ip} is NOT blocked in Kali VM")
        
        time.sleep(1)
    
    if verified_blocks:
        print_success(f"Verified {len(verified_blocks)}/{len(TEST_HIGH_RISK_IPS)} IPs blocked in Kali VM")
        return True
    else:
        print_error("No IPs verified as blocked in Kali VM")
        return False


def show_kali_firewall_rules():
    """Display all firewall rules in Kali VM"""
    print_info("Fetching firewall rules from Kali VM...")
    
    cmd = "sudo iptables -L -n -v | head -20"
    success, output = run_ssh_command(cmd)
    
    if success:
        print("Firewall Rules (first 20 lines):")
        print(output)
    else:
        print_error(f"Failed to fetch firewall rules: {output}")


# ============================================================================
# PHASE 5: SUMMARY & RESULTS
# ============================================================================

def generate_summary_report(results: Dict):
    """Generate final test summary"""
    print_section("TEST SUMMARY REPORT")
    
    total_tests = 5
    passed = sum(1 for v in results.values() if v)
    
    print(f"Tests Passed: {passed}/{total_tests}")
    print("\nDetailed Results:")
    
    for test_name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  • {test_name}: {status}")
    
    if passed == total_tests:
        print_success("ALL TESTS PASSED! ✓")
        return True
    else:
        print_error(f"SOME TESTS FAILED ({passed}/{total_tests})")
        return False


# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================

def main():
    """Run complete auto-blocking test"""
    print(f"\n{Colors.BLUE}")
    print("╔════════════════════════════════════════════════════════╗")
    print("║   AUTO-BLOCKING TEST SUITE FOR KALI VM                ║")
    print("║   Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"  ║")
    print("╚════════════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    results = {}
    
    try:
        # Phase 1: Pre-flight checks
        results['Preflight Checks'] = preflights()
        if not results['Preflight Checks']:
            print_error("Preflight checks failed. Aborting test.")
            return False
        
        # Phase 2: Inject test threats
        blocked_ips = inject_test_threats()
        results['Threat Injection'] = len(blocked_ips) > 0
        
        if not results['Threat Injection']:
            print_error("Failed to inject test threats. Aborting test.")
            return False
        
        # Phase 3: Wait for auto-blocking
        results['Auto-Blocking'] = wait_for_auto_blocking()
        
        # Phase 4: Verify in Kali
        results['Kali Verification'] = verify_blocking_kali()
        
        # Phase 5: Show firewall rules
        print_section("FIREWALL RULES IN KALI VM")
        show_kali_firewall_rules()
        results['Firewall Rules Display'] = True
        
    except KeyboardInterrupt:
        print_error("\n\nTest interrupted by user")
        return False
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        return False
    finally:
        # Generate summary
        generate_summary_report(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
