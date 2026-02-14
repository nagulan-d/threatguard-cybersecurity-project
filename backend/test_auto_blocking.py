"""
Test script for auto-blocking functionality
Demonstrates the auto-blocking system working with high-risk threats
"""
import sys
import os
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, _auto_block_high_risk_threats, BlockedThreat, AUTO_BLOCK_ENABLED

def test_auto_blocking():
    """Test the auto-blocking system with sample high-risk threats"""
    
    print("=" * 80)
    print("AUTO-BLOCKING SYSTEM TEST")
    print("=" * 80)
    
    # Sample high-risk threats for testing
    test_threats = [
        {
            "ip": "192.168.100.101",
            "ip_address": "192.168.100.101",
            "indicator": "192.168.100.101",
            "score": 95,
            "severity": "High",
            "Risk Category": "High",
            "type": "Ransomware C2",
            "Type": "Ransomware C2",
            "summary": "Ransomware command and control server detected",
            "Summary": "Ransomware command and control server detected"
        },
        {
            "ip": "192.168.100.102",
            "ip_address": "192.168.100.102",
            "indicator": "192.168.100.102",
            "score": 88,
            "severity": "High",
            "Risk Category": "High",
            "type": "Malware Host",
            "Type": "Malware Host",
            "summary": "Active malware distribution server",
            "Summary": "Active malware distribution server"
        },
        {
            "ip": "192.168.100.103",
            "ip_address": "192.168.100.103",
            "indicator": "192.168.100.103",
            "score": 82,
            "severity": "High",
            "Risk Category": "High",
            "type": "Phishing Server",
            "Type": "Phishing Server",
            "summary": "Phishing campaign infrastructure",
            "Summary": "Phishing campaign infrastructure"
        },
        {
            "ip": "192.168.100.104",
            "ip_address": "192.168.100.104",
            "indicator": "192.168.100.104",
            "score": 78,
            "severity": "High",
            "Risk Category": "High",
            "type": "DDoS Botnet Node",
            "Type": "DDoS Botnet Node",
            "summary": "Part of active DDoS botnet",
            "Summary": "Part of active DDoS botnet"
        },
        {
            "ip": "192.168.100.105",
            "ip_address": "192.168.100.105",
            "indicator": "192.168.100.105",
            "score": 45,  # Low score - should NOT be auto-blocked
            "severity": "Medium",
            "Risk Category": "Medium",
            "type": "Suspicious Activity",
            "Type": "Suspicious Activity",
            "summary": "Medium risk activity detected",
            "Summary": "Medium risk activity detected"
        }
    ]
    
    print(f"\n[TEST] Auto-blocking enabled: {AUTO_BLOCK_ENABLED}")
    print(f"[TEST] Testing with {len(test_threats)} sample threats")
    print(f"[TEST] Expected: 4 high-risk IPs to be blocked, 1 medium-risk IP to be skipped")
    print("\n" + "=" * 80)
    
    with app.app_context():
        # Show current blocked IPs before test
        existing_blocks = BlockedThreat.query.filter_by(is_active=True).all()
        print(f"\n[BEFORE] Currently blocked IPs: {len(existing_blocks)}")
        for block in existing_blocks:
            print(f"  - {block.ip_address} ({block.risk_category})")
        
        # Run auto-blocking
        print("\n[RUNNING] Auto-blocking system...")
        print("=" * 80 + "\n")
        
        _auto_block_high_risk_threats(test_threats)
        
        # Show results after test
        print("\n" + "=" * 80)
        all_blocks = BlockedThreat.query.filter_by(is_active=True).all()
        print(f"\n[AFTER] Total blocked IPs: {len(all_blocks)}")
        
        # Show newly blocked IPs
        test_ips = {t["ip"] for t in test_threats}
        newly_blocked = [b for b in all_blocks if b.ip_address in test_ips]
        
        print(f"[RESULT] Newly blocked from test: {len(newly_blocked)}")
        for block in newly_blocked:
            print(f"  ✓ {block.ip_address} - {block.threat_type} (Score: {block.risk_score})")
        
        # Show which IPs were skipped
        blocked_ips = {b.ip_address for b in all_blocks}
        skipped = [t for t in test_threats if t["ip"] not in blocked_ips]
        if skipped:
            print(f"\n[SKIPPED] IPs not blocked (score < threshold): {len(skipped)}")
            for threat in skipped:
                print(f"  ⊘ {threat['ip']} - {threat['type']} (Score: {threat['score']})")
    
    print("\n" + "=" * 80)
    print("TEST COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    test_auto_blocking()
