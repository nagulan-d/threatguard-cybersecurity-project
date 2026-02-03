"""
Add balanced threat data with proper High/Medium/Low distribution
"""
import json
import random
from datetime import datetime

# High-risk threats (score >= 75)
high_risk_threats = [
    {
        "indicator": "162.159.200.1",
        "type": "IPv4",
        "summary": "Suspicious IP address 162.159.200.1 detected in threat intelligence",
        "prevention": "Block IP address and monitor network traffic",
        "prevention_steps": "1) Add IP to firewall blocklist 2) Scan for compromised systems 3) Monitor outbound connections",
        "score": 82,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9001, "indicator": "162.159.200.1", "type": "IPv4"},
        "alert": True,
        "category": "Infrastructure",
        "severity": "High"
    },
    {
        "indicator": "malicious-site.com",
        "type": "domain",
        "summary": "Malicious domain malicious-site.com associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Add domain to blocklist 2) Alert users 3) Scan systems for compromise",
        "score": 79,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9002, "indicator": "malicious-site.com", "type": "domain"},
        "alert": True,
        "category": "Malware",
        "severity": "High"
    },
    {
        "indicator": "keylogger-host.org",
        "type": "domain",
        "summary": "Malicious domain keylogger-host.org associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Add domain to blocklist 2) Scan for keyloggers 3) Update credentials",
        "score": 85,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9003, "indicator": "keylogger-host.org", "type": "domain"},
        "alert": True,
        "category": "Web",
        "severity": "High"
    },
    {
        "indicator": "ransomware-c2.biz",
        "type": "domain",
        "summary": "Malicious domain ransomware-c2.biz associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain immediately 2) Isolate infected systems 3) Check backups",
        "score": 91,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9004, "indicator": "ransomware-c2.biz", "type": "domain"},
        "alert": True,
        "category": "Web",
        "severity": "High"
    },
    {
        "indicator": "apt-command.biz",
        "type": "domain",
        "summary": "Malicious domain apt-command.biz associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Hunt for APT indicators 3) Review logs for persistence",
        "score": 88,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9005, "indicator": "apt-command.biz", "type": "domain"},
        "alert": True,
        "category": "Vulnerabilities",
        "severity": "High"
    },
    {
        "indicator": "virus-download.info",
        "type": "domain",
        "summary": "Malicious domain virus-download.info associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Scan all systems 3) Update antivirus signatures",
        "score": 76,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9006, "indicator": "virus-download.info", "type": "domain"},
        "alert": True,
        "category": "Phishing",
        "severity": "High"
    },
    {
        "indicator": "trojan-server.net",
        "type": "domain",
        "summary": "Malicious domain trojan-server.net associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Scan for trojans 3) Review process list",
        "score": 83,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9007, "indicator": "trojan-server.net", "type": "domain"},
        "alert": True,
        "category": "Malware",
        "severity": "High"
    },
    {
        "indicator": "exploit-kit.org",
        "type": "domain",
        "summary": "Malicious domain exploit-kit.org associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Patch systems 3) Review vulnerability scans",
        "score": 87,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9008, "indicator": "exploit-kit.org", "type": "domain"},
        "alert": True,
        "category": "Vulnerabilities",
        "severity": "High"
    },
]

# Medium-risk threats (score 50-74)
medium_risk_threats = [
    {
        "indicator": "nation-state-malware.info",
        "type": "domain",
        "summary": "Malicious domain nation-state-malware.info associated with threat activity",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Review security logs 3) Check for lateral movement",
        "score": 67,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9009, "indicator": "nation-state-malware.info", "type": "domain"},
        "alert": False,
        "category": "Vulnerabilities",
        "severity": "Medium"
    },
    {
        "indicator": "suspicious-cdn.net",
        "type": "domain",
        "summary": "Suspicious domain suspicious-cdn.net detected in threat intelligence",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Monitor traffic 2) Block if confirmed malicious 3) Review access logs",
        "score": 62,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9010, "indicator": "suspicious-cdn.net", "type": "domain"},
        "alert": False,
        "category": "Infrastructure",
        "severity": "Medium"
    },
    {
        "indicator": "phishing-attempt.com",
        "type": "domain",
        "summary": "Phishing domain phishing-attempt.com associated with credential harvesting",
        "prevention": "Block the domain/URL and investigate referrals",
        "prevention_steps": "1) Block domain 2) Alert users 3) Review email logs",
        "score": 68,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9011, "indicator": "phishing-attempt.com", "type": "domain"},
        "alert": False,
        "category": "Phishing",
        "severity": "Medium"
    },
]

# Low-risk threats (score < 50)
low_risk_threats = [
    {
        "indicator": "104.244.42.1",
        "type": "IPv4",
        "summary": "Suspicious IP address 104.244.42.1 detected in threat intelligence",
        "prevention": "Monitor IP address and network traffic",
        "prevention_steps": "1) Monitor traffic patterns 2) Review logs 3) Block if activity increases",
        "score": 42,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9012, "indicator": "104.244.42.1", "type": "IPv4"},
        "alert": False,
        "category": "Web",
        "severity": "Low"
    },
    {
        "indicator": "unknown-scanner.net",
        "type": "domain",
        "summary": "Possible scanning activity from unknown-scanner.net",
        "prevention": "Monitor the domain and traffic patterns",
        "prevention_steps": "1) Monitor traffic 2) Review firewall logs 3) Increase alerting if needed",
        "score": 38,
        "timestamp": "2026-01-27T00:00:00",
        "otx": {"id": 9013, "indicator": "unknown-scanner.net", "type": "domain"},
        "alert": False,
        "category": "Infrastructure",
        "severity": "Low"
    },
]

def main():
    # Load existing threats
    with open("recent_threats.json", "r", encoding="utf-8") as f:
        existing_threats = json.load(f)
    
    print(f"📊 Current threat count: {len(existing_threats)}")
    
    # Add new threats
    all_threats = existing_threats + high_risk_threats + medium_risk_threats + low_risk_threats
    
    # Remove duplicates based on indicator
    seen = set()
    unique_threats = []
    for threat in all_threats:
        if threat["indicator"] not in seen:
            seen.add(threat["indicator"])
            unique_threats.append(threat)
    
    # Count by risk level
    high_count = sum(1 for t in unique_threats if t.get("score", 0) >= 75)
    medium_count = sum(1 for t in unique_threats if 50 <= t.get("score", 0) < 75)
    low_count = sum(1 for t in unique_threats if t.get("score", 0) < 50)
    
    print(f"\n📊 New threat distribution:")
    print(f"   🔴 High (≥75): {high_count} threats")
    print(f"   ⚠️ Medium (50-74): {medium_count} threats")
    print(f"   🟢 Low (<50): {low_count} threats")
    print(f"   Total: {len(unique_threats)} threats")
    
    # Save back to file
    with open("recent_threats.json", "w", encoding="utf-8") as f:
        json.dump(unique_threats, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Successfully updated recent_threats.json")

if __name__ == "__main__":
    main()
