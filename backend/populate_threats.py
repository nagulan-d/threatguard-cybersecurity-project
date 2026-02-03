"""
Populate threat cache with realistic IP threats for testing
Generates 20 diverse IP threats with varying risk scores
"""
import json
import random
from datetime import datetime, timedelta

# Realistic threat IPs and descriptions
THREAT_TEMPLATES = [
    {"ip": "185.220.101.{}", "type": "Tor Exit Node", "base_score": 75},
    {"ip": "45.142.120.{}", "type": "Brute Force Scanner", "base_score": 82},
    {"ip": "91.219.237.{}", "type": "Malware C&C Server", "base_score": 95},
    {"ip": "193.163.125.{}", "type": "Port Scanner", "base_score": 68},
    {"ip": "104.244.78.{}", "type": "DDoS Botnet", "base_score": 88},
    {"ip": "198.98.51.{}", "type": "Phishing Campaign", "base_score": 91},
    {"ip": "176.123.8.{}", "type": "Credential Stuffing", "base_score": 79},
    {"ip": "195.154.181.{}", "type": "Exploit Scanner", "base_score": 85},
    {"ip": "142.93.123.{}", "type": "Ransomware Infrastructure", "base_score": 97},
    {"ip": "159.65.141.{}", "type": "Web Application Attack", "base_score": 73}
]

CATEGORIES = ["Infrastructure", "Malware", "Phishing", "DDoS", "Ransomware", "Vulnerabilities"]

def generate_threats(count=20):
    threats = []
    now = datetime.utcnow()
    
    for i in range(count):
        template = THREAT_TEMPLATES[i % len(THREAT_TEMPLATES)]
        last_octet = random.randint(10, 250)
        ip_address = template["ip"].format(last_octet)
        
        # Randomize score slightly
        score = template["base_score"] + random.randint(-5, 5)
        score = max(60, min(100, score))  # Clamp between 60-100
        
        # Determine severity
        if score >= 80:
            severity = "High"
        elif score >= 60:
            severity = "Medium"
        else:
            severity = "Low"
        
        # Random category
        category = random.choice(CATEGORIES)
        
        # Generate timestamp within last 24 hours
        hours_ago = random.randint(0, 24)
        timestamp = (now - timedelta(hours=hours_ago)).isoformat()
        
        threat = {
            "indicator": ip_address,
            "ip": ip_address,
            "type": "IPv4",
            "summary": f"{ip_address} - {template['type']} detected. Block or monitor connections from this IP.",
            "prevention": "Block this IP address at firewall level and monitor all connection attempts.",
            "prevention_steps": "1) Add firewall rule to block IP 2) Check access logs 3) Create IDS rule to monitor traffic",
            "score": score,
            "severity_score": score,
            "severity": severity,
            "category": category,
            "timestamp": timestamp,
            "alert": score >= 75  # Only alert for high-risk threats
        }
        
        threats.append(threat)
    
    return threats

if __name__ == "__main__":
    threats = generate_threats(20)
    
    with open('recent_threats.json', 'w', encoding='utf-8') as f:
        json.dump(threats, f, indent=2)
    
    print(f"✓ Generated {len(threats)} IP threats")
    print(f"  - High-risk (≥80): {sum(1 for t in threats if t['score'] >= 80)}")
    print(f"  - Medium-risk (60-79): {sum(1 for t in threats if 60 <= t['score'] < 80)}")
    print(f"  - Auto-alerts (≥75): {sum(1 for t in threats if t['alert'])}")
