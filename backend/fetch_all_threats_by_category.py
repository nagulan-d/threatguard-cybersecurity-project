"""
Fetch ALL threats from AlienVault OTX organized by category.
This script fetches comprehensive threat data across all categories.
"""
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
API_EXPORT_URL = os.getenv("API_EXPORT_URL", "https://otx.alienvault.com/api/v1/indicators/export")
OUTPUT_FILE = "recent_threats.json"

# Categories matching frontend dropdown
CATEGORIES = [
    "Phishing",
    "Ransomware", 
    "Malware",
    "DDoS Attacks",
    "Vulnerability Exploits",
    "Current Threats"
]

def categorize_indicator(indicator):
    """Categorize based on type and tags."""
    indicator_type = str(indicator.get("type", "")).lower()
    tags = []
    
    # Extract tags
    if "tags" in indicator:
        tags.extend(str(t).lower() for t in indicator.get("tags", []))
    
    pulse_info = indicator.get("pulse_info", {})
    if isinstance(pulse_info, dict):
        for pulse in pulse_info.get("pulses", []):
            if "tags" in pulse:
                tags.extend(str(t).lower() for t in pulse.get("tags", []))
    
    tags_str = " ".join(tags)
    
    # Categorize
    if any(kw in tags_str for kw in ["phish", "credential", "spoof"]):
        return "Phishing"
    elif any(kw in tags_str for kw in ["ransom", "locker", "encryptor"]):
        return "Ransomware"
    elif any(kw in tags_str for kw in ["malware", "trojan", "virus", "worm", "botnet"]):
        return "Malware"
    elif any(kw in tags_str for kw in ["ddos", "denial", "dos"]):
        return "DDoS Attacks"
    elif any(kw in tags_str for kw in ["cve", "exploit", "vulnerab", "rce", "0day", "zero-day"]):
        return "Vulnerability Exploits"
    elif indicator_type in ["ipv4", "ip", "hostname", "dns", "domain"]:
        return "Current Threats"
    elif indicator_type in ["url", "uri"]:
        return "Malware"
    else:
        return "Other"

def calculate_severity_score(indicator):
    """Calculate severity score based on pulse data and reputation signals."""
    pulse_info = indicator.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    
    # Base score starts higher for better distribution
    score = 50.0
    
    # Pulse count bonus (more pulses = higher severity)
    pulse_count = len(pulses)
    if pulse_count >= 10:
        score += 30
    elif pulse_count >= 5:
        score += 20
    elif pulse_count >= 2:
        score += 10
    elif pulse_count >= 1:
        score += 5
    
    # Confidence bonus
    confidences = []
    for pulse in pulses:
        conf = pulse.get("confidence")
        if conf:
            try:
                confidences.append(float(conf))
            except:
                pass
    
    if confidences:
        avg_conf = sum(confidences) / len(confidences)
        score += (avg_conf / 100) * 15
    
    # Reference bonus (reputable sources)
    ref_count = sum(len(pulse.get("references", [])) for pulse in pulses)
    if ref_count >= 5:
        score += 15
    elif ref_count >= 2:
        score += 10
    elif ref_count >= 1:
        score += 5
    
    # Tag-based severity boost
    tags_str = " ".join([str(t).lower() for pulse in pulses for t in pulse.get("tags", [])])
    high_risk_keywords = ["apt", "backdoor", "c2", "command and control", "ransomware", 
                          "trojan", "malware", "exploit", "0day", "cve-", "remote code"]
    
    for keyword in high_risk_keywords:
        if keyword in tags_str:
            score += 5
            break
    
    score = min(score, 100.0)
    
    # Determine severity level
    if score >= 75:
        severity = "High"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "Low"
    
    return round(score, 2), severity

def fetch_all_threats():
    """Fetch comprehensive threat data from OTX in batches."""
    headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
    
    all_indicators = []
    
    # Fetch in multiple batches to avoid API limits
    # OTX API limits: max 100-200 per request
    batches = [
        {"limit": 200, "modified_since": "7d"},   # Last 7 days
        {"limit": 200, "modified_since": "30d"},  # Last 30 days
    ]
    
    print(f"🔍 Fetching ALL threats from AlienVault OTX in batches...\n")
    
    for i, params in enumerate(batches, 1):
        print(f"📦 Batch {i}/{len(batches)}: Limit={params['limit']}, Range={params['modified_since']}")
        
        try:
            response = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            
            # Parse response
            try:
                data = response.json()
            except:
                # Handle NDJSON format
                lines = [l.strip() for l in response.text.splitlines() if l.strip()]
                data = [json.loads(line) for line in lines]
            
            # Extract indicators
            if isinstance(data, dict):
                indicators = data.get("results", []) or data.get("indicators", [])
            elif isinstance(data, list):
                indicators = data
            else:
                indicators = []
            
            print(f"   ✅ Fetched {len(indicators)} indicators")
            all_indicators.extend(indicators)
            
        except requests.exceptions.HTTPError as e:
            print(f"   ⚠️  HTTP Error: {e}")
            continue
        except Exception as e:
            print(f"   ❌ Error: {e}")
            continue
    
    # Remove duplicates by indicator value
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        indicator_val = ind.get("indicator", str(ind.get("id", "")))
        if indicator_val not in seen:
            seen.add(indicator_val)
            unique_indicators.append(ind)
    
    print(f"\n✅ Total fetched: {len(all_indicators)} ({len(unique_indicators)} unique)\n")
    
    # Process and categorize
    threats_by_category = {cat: [] for cat in CATEGORIES}
    threats_by_category["Other"] = []
    all_threats = []
    high_threats = []
    
    for indicator in unique_indicators:
        # Filter allowed types
        ind_type = str(indicator.get("type", "")).lower()
        if ind_type not in ["ipv4", "ip", "hostname", "dns", "domain", "url", "uri", "md5", "sha1", "sha256"]:
            continue
        
        # Calculate severity
        score, severity = calculate_severity_score(indicator)
        
        # Categorize
        category = categorize_indicator(indicator)
        
        # Build threat object
        threat = {
            "indicator": indicator.get("indicator", ""),
            "type": indicator.get("type", ""),
            "category": category,
            "severity": severity,
            "score": score,
            "summary": f"{category} threat: {indicator.get('indicator', '')[:50]}",
            "prevention": "Block this indicator and monitor for related activity",
            "timestamp": indicator.get("modified") or indicator.get("created") or datetime.utcnow().isoformat(),
            "alert": score >= 75,
            "pulse_count": len(indicator.get("pulse_info", {}).get("pulses", [])),
            "ip": indicator.get("indicator", "") if ind_type == "ipv4" else None
        }
        
        threats_by_category[category].append(threat)
        all_threats.append(threat)
        
        # Track high-severity threats
        if score >= 75:
            high_threats.append(threat)
    
    # Save all threats
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_threats, f, indent=2)
    
    # Print statistics
    print(f"\n{'='*60}")
    print(f"📊 THREAT STATISTICS")
    print(f"{'='*60}")
    print(f"Total Threats: {len(all_threats)}")
    print(f"\n📁 By Category:")
    for cat in CATEGORIES + ["Other"]:
        count = len(threats_by_category[cat])
        high_count = len([t for t in threats_by_category[cat] if t["score"] >= 75])
        print(f"   {cat}: {count} threats ({high_count} high-severity)")
    
    print(f"\n🔥 High-Severity Threats (Score ≥ 75): {len(high_threats)}")
    print(f"⚠️  Medium-Severity (50-74): {len([t for t in all_threats if 50 <= t['score'] < 75])}")
    print(f"ℹ️  Low-Severity (<50): {len([t for t in all_threats if t['score'] < 50])}")
    print(f"\n✅ Saved to: {OUTPUT_FILE}")
    print(f"{'='*60}\n")
    
    return all_threats

if __name__ == "__main__":
    if not API_KEY:
        print("❌ ERROR: API_KEY not set in .env file")
        exit(1)
    
    fetch_all_threats()
