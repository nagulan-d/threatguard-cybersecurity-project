"""
Live Threat Fetcher - Fetches fresh threats from AlienVault OTX on every request
Ensures no duplicates and different threats on each refresh
"""
import os
import json
import requests
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Set
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
API_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
SEEN_THREATS_FILE = "seen_threats.json"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def categorize_threat(indicator_type: str, tags: List[str]) -> str:
    """Categorize threat based on type and tags."""
    tags_str = " ".join(tags).lower()
    
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

def calculate_severity(indicator: dict) -> tuple:
    """Calculate severity score based on pulse data and tags."""
    pulse_info = indicator.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    
    # Base score
    score = 55.0
    
    # Pulse count bonus
    pulse_count = len(pulses)
    if pulse_count >= 15:
        score += 30
    elif pulse_count >= 10:
        score += 25
    elif pulse_count >= 5:
        score += 15
    elif pulse_count >= 2:
        score += 10
    elif pulse_count >= 1:
        score += 5
    
    # Tags-based severity
    all_tags = []
    for pulse in pulses:
        all_tags.extend(pulse.get("tags", []))
    
    tags_str = " ".join(str(t).lower() for t in all_tags)
    
    # High-risk keywords boost
    high_risk = ["apt", "backdoor", "c2", "c&c", "ransomware", "trojan", "exploit", 
                 "0day", "cve-", "remote", "rce", "backdoor", "botnet"]
    for keyword in high_risk:
        if keyword in tags_str:
            score += 8
            break
    
    # Confidence from pulses
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
        score += (avg_conf / 100) * 10
    
    score = min(score, 100.0)
    
    # Determine severity level
    if score >= 75:
        severity = "High"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "Low"
    
    return round(score, 2), severity

def fetch_live_threats(limit: int = 20, category: str = None, offset_hours: int = 0) -> List[Dict]:
    """
    Fetch LIVE threats from OTX API with no duplicates.
    
    Args:
        limit: Number of threats to return
        category: Filter by category (None = all)
        offset_hours: Offset for time-based pagination (0, 6, 12, 24, etc.)
    
    Returns:
        List of fresh threat objects
    """
    seen_indicators = set()
    
    headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
    
    # Use progressive time windows - start with very recent
    time_windows = ["1h", "3h", "6h", "12h", "24h", "3d", "7d"]
    
    print(f"[LIVE FETCH] Fetching fresh threats from OTX...")
    
    threats = []
    attempts = 0
    max_attempts = len(time_windows)
    
    for time_window in time_windows:
        if len(threats) >= limit:
            break
        
        attempts += 1
        
        # Fetch more than needed to account for duplicates
        fetch_limit = min((limit - len(threats)) * 2 + 20, 100)  # Smaller batches
        
        params = {
            "limit": fetch_limit,
            "modified_since": time_window
        }
        
        print(f"[LIVE FETCH] Attempt {attempts}: Fetching {fetch_limit} indicators (modified_since={time_window})...")
        
        try:
            response = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=20)
            
            # Handle different response codes
            if response.status_code == 500:
                print(f"[LIVE FETCH] Server error for {time_window}, trying next window...")
                continue
            
            response.raise_for_status()
            
            # Parse response
            try:
                data = response.json()
            except:
                lines = [l.strip() for l in response.text.splitlines() if l.strip()]
                data = [json.loads(line) for line in lines[:fetch_limit]]
            
            # Extract indicators
            if isinstance(data, dict):
                indicators = data.get("results", []) or data.get("indicators", [])
            elif isinstance(data, list):
                indicators = data
            else:
                indicators = []
            
            if not indicators:
                print(f"[LIVE FETCH] No indicators in response for {time_window}")
                continue
            
            print(f"[LIVE FETCH] Received {len(indicators)} indicators from OTX")
            
            # Process indicators
            for indicator in indicators:
                if len(threats) >= limit:
                    break
                
                ind_type = str(indicator.get("type", "")).lower()
                ind_value = indicator.get("indicator", "")
                
                # Skip if not allowed type (IP-only)
                if ind_type not in ["ipv4", "ip"]:
                    continue

                if not _is_ip(ind_value):
                    continue
                
                # Skip if already shown in this request
                if ind_value in seen_indicators:
                    continue
                
                # Extract tags
                tags = list(indicator.get("tags", []))
                pulse_info = indicator.get("pulse_info", {})
                if isinstance(pulse_info, dict):
                    for pulse in pulse_info.get("pulses", []):
                        tags.extend(pulse.get("tags", []))
                
                # Categorize
                threat_category = categorize_threat(ind_type, tags)
                
                # Filter by category if specified
                if category and category != "All" and threat_category != category:
                    continue
                
                # Calculate severity
                score, severity = calculate_severity(indicator)
                
                # Build threat object
                threat = {
                    "indicator": ind_value,
                    "ip": ind_value if ind_type == "ipv4" else None,
                    "type": ind_type.upper(),
                    "category": threat_category,
                    "severity": severity,
                    "score": score,
                    "summary": f"{threat_category} threat detected: {ind_value[:50]}",
                    "prevention": f"Block {ind_value} and monitor for related activity",
                    "prevention_steps": f"1) Block {ind_value} at firewall 2) Check logs 3) Scan affected systems",
                    "timestamp": indicator.get("modified") or indicator.get("created") or datetime.utcnow().isoformat(),
                    "alert": score >= 75,
                    "pulse_count": len(indicator.get("pulse_info", {}).get("pulses", [])),
                    "reputation": (100 - score) / 100.0,
                    "tags": tags[:5]  # Include some tags
                }
                
                threats.append(threat)
                seen_indicators.add(ind_value)
            
            # If we got enough threats, break outer loop
            if len(threats) >= limit:
                break
            
        except requests.exceptions.HTTPError as e:
            print(f"[LIVE FETCH] HTTP Error for {time_window}: {e}")
            continue
        except requests.exceptions.Timeout:
            print(f"[LIVE FETCH] Timeout for {time_window}")
            continue
        except requests.exceptions.RequestException as e:
            print(f"[LIVE FETCH] Request error for {time_window}: {e}")
            continue
        except Exception as e:
            print(f"[LIVE FETCH] Error for {time_window}: {e}")
            continue
    
    print(f"[LIVE FETCH] Returning {len(threats)} fresh threats")
    
    return threats

def reset_shown_threats():
    """No-op: live fetcher does not persist seen threats."""
    print("[LIVE FETCH] Reset shown threats (no-op)")

if __name__ == "__main__":
    # Test
    print("Testing Live Threat Fetcher...\n")
    
    threats = fetch_live_threats(limit=10)
    
    print(f"\nFetched {len(threats)} threats:")
    for i, t in enumerate(threats[:5], 1):
        print(f"{i}. {t['category']:20} | {t['indicator']:30} | Score: {t['score']}")
