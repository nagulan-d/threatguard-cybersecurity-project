"""
Add Real IP-Based High-Risk Threats to Cache
This script adds sample high-risk threats with real IP addresses to test auto-blocking
"""
import json
import os
from datetime import datetime

THREATS_OUTPUT = "recent_threats.json"

# Sample high-risk threats with real IP addresses (using example/test IPs)
sample_threats = [
    {
        "Risk Category": "High",
        "Indicator": "192.0.2.100",
        "IP Address": "192.0.2.100",
        "ip": "192.0.2.100",
        "Type": "Ransomware C2",
        "type": "Ransomware C2",
        "Summary": "Ransomware command and control server - encrypts files and demands payment",
        "summary": "Ransomware command and control server - encrypts files and demands payment",
        "Score": 95,
        "score": 95,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Ransomware"
    },
    {
        "Risk Category": "High",
        "Indicator": "198.51.100.50",
        "IP Address": "198.51.100.50",
        "ip": "198.51.100.50",
        "Type": "Malware Host",
        "type": "Malware Host",
        "Summary": "Active malware distribution server - hosts trojan and virus payloads",
        "summary": "Active malware distribution server - hosts trojan and virus payloads",
        "Score": 88,
        "score": 88,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Malware"
    },
    {
        "Risk Category": "High",
        "Indicator": "203.0.113.75",
        "IP Address": "203.0.113.75",
        "ip": "203.0.113.75",
        "Type": "Phishing Server",
        "type": "Phishing Server",
        "Summary": "Phishing campaign infrastructure - credential harvesting active",
        "summary": "Phishing campaign infrastructure - credential harvesting active",
        "Score": 82,
        "score": 82,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Phishing"
    },
    {
        "Risk Category": "High",
        "Indicator": "192.0.2.200",
        "IP Address": "192.0.2.200",
        "ip": "192.0.2.200",
        "Type": "DDoS Botnet Node",
        "type": "DDoS Botnet Node",
        "Summary": "Part of active DDoS botnet - participating in amplification attacks",
        "summary": "Part of active DDoS botnet - participating in amplification attacks",
        "Score": 78,
        "score": 78,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "DDoS"
    },
    {
        "Risk Category": "High",
        "Indicator": "198.51.100.150",
        "IP Address": "198.51.100.150",
        "ip": "198.51.100.150",
        "Type": "Exploit Host",
        "type": "Exploit Host",
        "Summary": "Hosting exploit kits - targeting known vulnerabilities",
        "summary": "Hosting exploit kits - targeting known vulnerabilities",
        "Score": 85,
        "score": 85,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Vulnerability Exploits"
    },
    {
        "Risk Category": "High",
        "Indicator": "203.0.113.89",
        "IP Address": "203.0.113.89",
        "ip": "203.0.113.89",
        "Type": "Botnet C2",
        "type": "Botnet C2",
        "Summary": "Botnet command and control - coordinating infected devices",
        "summary": "Botnet command and control - coordinating infected devices",
        "Score": 91,
        "score": 91,
        "severity": "High",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Malware"
    },
    {
        "Risk Category": "Medium",
        "Indicator": "192.0.2.50",
        "IP Address": "192.0.2.50",
        "ip": "192.0.2.50",
        "Type": "Suspicious Activity",
        "type": "Suspicious Activity",
        "Summary": "Potentially compromised host - monitoring recommended",
        "summary": "Potentially compromised host - monitoring recommended",
        "Score": 55,
        "score": 55,
        "severity": "Medium",
        "Detected When": datetime.utcnow().isoformat() + 'Z',
        "category": "Unknown"
    }
]

def add_ip_threats():
    """Add IP-based threats to the cache"""
    
    print("=" * 80)
    print("ADD IP-BASED HIGH-RISK THREATS TO CACHE")
    print("=" * 80)
    
    # Load existing cache if it exists
    existing_threats = []
    if os.path.exists(THREATS_OUTPUT):
        try:
            with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                existing_threats = json.load(f)
            print(f"\n[INFO] Loaded {len(existing_threats)} existing threats from cache")
        except Exception as e:
            print(f"[WARN] Could not load existing cache: {e}")
    else:
        print(f"\n[INFO] No existing cache found - will create new one")
    
    # Filter out duplicates (same IP)
    existing_ips = {
        t.get("ip") or t.get("IP Address") or t.get("indicator")
        for t in existing_threats
    }
    
    new_threats = []
    for threat in sample_threats:
        ip = threat.get("ip")
        if ip not in existing_ips:
            new_threats.append(threat)
    
    print(f"[INFO] Adding {len(new_threats)} new IP-based threats")
    
    # Combine existing and new threats
    all_threats = existing_threats + new_threats
    
    # Save to cache
    try:
        with open(THREATS_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(all_threats, f, indent=2)
        print(f"\n[OK] Saved {len(all_threats)} total threats to cache")
    except Exception as e:
        print(f"[ERROR] Failed to save cache: {e}")
        return
    
    # Show statistics
    high_risk = [t for t in all_threats if t.get("score", 0) >= 75]
    medium_risk = [t for t in all_threats if 50 <= t.get("score", 0) < 75]
    low_risk = [t for t in all_threats if t.get("score", 0) < 50]
    
    print(f"\n[STATS] Cache Statistics:")
    print(f"  Total threats: {len(all_threats)}")
    print(f"  High-risk (score >= 75): {len(high_risk)}")
    print(f"  Medium-risk (50-74): {len(medium_risk)}")
    print(f"  Low-risk (< 50): {len(low_risk)}")
    
    print(f"\n[PREVIEW] New IP-based threats added:")
    for threat in new_threats:
        ip = threat.get("ip")
        score = threat.get("score")
        threat_type = threat.get("type")
        print(f"  • {ip} - {threat_type} (Score: {score})")
    
    print("\n" + "=" * 80)
    print("[NEXT STEPS]")
    print("=" * 80)
    print("\n1. Run: python manual_auto_block.py")
    print("   This will auto-block the high-risk IPs")
    print("\n2. Run: python check_blocked_db.py")
    print("   This will show the blocked IPs in the database")
    print("\n3. Login to Admin Dashboard and go to 'Blocked Threats' tab")
    print("   Filter by: blocked_by='admin' and is_active='true'")
    print("   You should see the auto-blocked IPs")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    add_ip_threats()
