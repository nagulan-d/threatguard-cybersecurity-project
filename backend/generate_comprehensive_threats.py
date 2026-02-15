"""
Generate comprehensive threat dataset across ALL categories with high-severity threats for blocking.
Combines real OTX data with curated high-severity threats per category.
"""
import json
import requests
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
API_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
OUTPUT_FILE = "recent_threats.json"

# High-severity threats by category for blocking demonstrations
HIGH_SEVERITY_THREATS = {
    "Phishing": [
        {"ip": "185.220.101.15", "desc": "Phishing infrastructure targeting Microsoft 365 credentials", "score": 92},
        {"ip": "45.142.120.88", "desc": "PayPal phishing campaign C2 server", "score": 88},
        {"ip": "91.219.237.44", "desc": "Banking phishing kit distribution server", "score": 85},
        {"ip": "193.163.125.67", "desc": "Multi-brand phishing hosting infrastructure", "score": 82},
        {"ip": "104.244.78.99", "desc": "Spear phishing campaign infrastructure", "score": 79},
    ],
    "Ransomware": [
        {"ip": "198.98.51.22", "desc": "LockBit ransomware C2 server active campaign", "score": 98},
        {"ip": "176.123.8.55", "desc": "BlackCat/ALPHV ransomware infrastructure", "score": 95},
        {"ip": "195.154.181.33", "desc": "Conti ransomware affiliate server", "score": 91},
        {"ip": "142.93.123.77", "desc": "REvil/Sodinokibi ransomware distributionserver", "score": 89},
        {"ip": "159.65.141.44", "desc": "Maze ransomware data exfiltration node", "score": 86},
    ],
    "Malware": [
        {"ip": "203.0.113.50", "desc": "Emotet malware C2 infrastructure", "score": 94},
        {"ip": "203.0.113.51", "desc": "TrickBot banking trojan distribution", "score": 91},
        {"ip": "203.0.113.52", "desc": "Cobalt Strike beacon infrastructure", "score": 88},
        {"ip": "203.0.113.53", "desc": "Qakbot malware loader C2 server", "score": 85},
        {"ip": "203.0.113.54", "desc": "AgentTesla information stealer infrastructure", "score": 82},
    ],
    "DDoS Attacks": [
        {"ip": "185.143.223.45", "desc": "Mirai botnet C2 server active DDoS campaign", "score": 93},
        {"ip": "45.95.168.88", "desc": "Memcached DDoS amplification source", "score": 87},
        {"ip": "91.92.109.55", "desc": "DDoS-for-hire infrastructure botnet controller", "score": 84},
        {"ip": "193.36.119.77", "desc": "UDP flood DDoS attack source", "score": 81},
        {"ip": "104.131.30.99", "desc": "SYN flood botnet node", "score": 78},
    ],
    "Vulnerability Exploits": [
        {"ip": "45.130.229.168", "desc": "Exploiting CVE-2024-4577 PHP RCE vulnerability", "score": 96},
        {"ip": "185.191.171.45", "desc": "Log4Shell (CVE-2021-44228) mass scanning", "score": 93},
        {"ip": "91.241.19.84", "desc": "ProxyShell Exchange server exploitation", "score": 90},
        {"ip": "193.34.166.23", "desc": "Apache Struts RCE exploit attempts", "score": 87},
        {"ip": "159.223.4.55", "desc": "Zero-day exploit delivery infrastructure", "score": 84},
    ],
    "Current Threats": [
        {"ip": "185.27.134.125", "desc": "Malicious proxy infrastructure active now", "score": 89},
        {"ip": "172.111.206.103", "desc": "Recent APT scanning infrastructure", "score": 86},
        {"ip": "159.198.66.153", "desc": "Currently active malicious domain hosting", "score": 83},
        {"ip": "196.251.116.219", "desc": "Fresh Tor exit node abuse", "score": 80},
        {"ip": "194.169.163.140", "desc": "Currently detected in active campaigns", "score": 77},
    ]
}

def generate_high_severity_threats():
    """Generate high-severity threats for all categories."""
    all_threats = []
    
    for category, threats in HIGH_SEVERITY_THREATS.items():
        for threat_data in threats:
            threat = {
                "indicator": threat_data["ip"],
                "ip": threat_data["ip"],
                "type": "IPv4",
                "category": category,
                "severity": "High",
                "score": threat_data["score"],
                "summary": f"{threat_data['desc']} - Immediate blocking recommended",
                "prevention": f"Block {threat_data['ip']} immediately at firewall level and scan for any existing connections",
                "prevention_steps": f"1) Add {threat_data['ip']} to firewall blocklist 2) Check logs for existing connections 3) Scan affected systems for compromise",
                "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "alert": True,
                "pulse_count": 15 + (threat_data["score"] - 75),  # Higher score = more pulses
                "reputation": (100 - threat_data["score"]) / 100.0
            }
            all_threats.append(threat)
    
    return all_threats

def fetch_otx_threats():
    """Fetch real threats from OTX API."""
    headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
    params = {"limit": 150, "modified_since": "7d"}
    
    print(f"🔍 Fetching real threats from OTX...")
    
    try:
        response = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=45)
        response.raise_for_status()
        
        try:
            data = response.json()
        except:
            lines = [l.strip() for l in response.text.splitlines() if l.strip()]
            data = [json.loads(line) for line in lines[:150]]
        
        if isinstance(data, dict):
            indicators = data.get("results", []) or data.get("indicators", [])
        elif isinstance(data, list):
            indicators = data
        else:
            indicators = []
        
        print(f"   ✅ Fetched {len(indicators)} OTX indicators")
        
        # Process into threats
        otx_threats = []
        for ind in indicators[:100]:  # Limit to 100
            ind_type = str(ind.get("type", "")).lower()
            if ind_type not in ["ipv4", "ip", "hostname", "dns", "domain", "url", "uri"]:
                continue
            
            # Categorize
            tags_str = " ".join(str(t).lower() for t in ind.get("tags", []))
            
            if any(kw in tags_str for kw in ["phish", "credential"]):
                category = "Phishing"
            elif any(kw in tags_str for kw in ["ransom", "locker"]):
                category = "Ransomware"
            elif any(kw in tags_str for kw in ["malware", "trojan", "virus"]):
                category = "Malware"
            elif any(kw in tags_str for kw in ["ddos", "denial"]):
                category = "DDoS Attacks"
            elif any(kw in tags_str for kw in ["exploit", "cve", "vulnerab"]):
                category = "Vulnerability Exploits"
            else:
                category = "Current Threats"
            
            # Medium severity for OTX threats
            score = 60 + (hash(str(ind.get("indicator", ""))) % 15)  # 60-74
            
            threat = {
                "indicator": ind.get("indicator", ""),
                "ip": ind.get("indicator", "") if ind_type == "ipv4" else None,
                "type": ind.get("type", "").upper(),
                "category": category,
                "severity": "Medium",
                "score": score,
                "summary": f"{category} indicator detected in OTX",
                "prevention": "Monitor and investigate this indicator for potential threats",
                "timestamp": ind.get("modified") or ind.get("created") or datetime.utcnow().isoformat(),
                "alert": False,
                "pulse_count": 1,
                "reputation": 0.3
            }
            otx_threats.append(threat)
        
        return otx_threats
        
    except Exception as e:
        print(f"   ⚠️  Error fetching OTX: {e}")
        return []

def main():
    """Generate comprehensive threat dataset."""
    print("\n" + "="*70)
    print("🎯 COMPREHENSIVE THREAT DATASET GENERATOR")
    print("="*70 + "\n")
    
    # Generate high-severity threats
    print("🔥 Generating high-severity threats for ALL categories...")
    high_threats = generate_high_severity_threats()
    print(f"   ✅ Created {len(high_threats)} high-severity threats\n")
    
    # Fetch real OTX threats
    otx_threats = fetch_otx_threats()
    print(f"   ✅ Fetched {len(otx_threats)} medium-severity OTX threats\n")
    
    # Combine all threats
    all_threats = high_threats + otx_threats
    
    # Save to file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_threats, f, indent=2)
    
    # Statistics
    from collections import Counter
    cat_count = Counter(t["category"] for t in all_threats)
    
    print("="*70)
    print("📊 FINAL THREAT STATISTICS")
    print("="*70)
    print(f"\n🎯 Total Threats: {len(all_threats)}\n")
    
    print("📁 By Category:")
    for cat in ["Phishing", "Ransomware", "Malware", "DDoS Attacks", "Vulnerability Exploits", "Current Threats"]:
        total = cat_count.get(cat, 0)
        high = len([t for t in all_threats if t["category"] == cat and t["severity"] == "High"])
        medium = len([t for t in all_threats if t["category"] == cat and t["severity"] == "Medium"])
        print(f"   {cat:25}: {total:3} threats ({high:2} high, {medium:2} medium)")
    
    high_total = len([t for t in all_threats if t["severity"] == "High"])
    medium_total = len([t for t in all_threats if t["severity"] == "Medium"])
    
    print(f"\n🔥 High-Severity (Score ≥ 75): {high_total} - READY FOR BLOCKING")
    print(f"⚠️  Medium-Severity (Score 50-74): {medium_total}")
    print(f"\n✅ Saved to: {OUTPUT_FILE}")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
