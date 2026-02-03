"""
Strict Cyber Threat Intelligence Processor
Implements mandatory IP-based threat validation and risk categorization
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate IPv4 or IPv6 address
    Returns False for null, N/A, empty, or invalid IPs
    """
    if not ip_str or ip_str in ["null", "N/A", "n/a", "", "None"]:
        return False
    
    # IPv4 validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    # IPv6 validation (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    if re.match(ipv6_pattern, ip_str):
        return True
    
    return False


def extract_ip_from_indicator(indicator: Dict[str, Any]) -> Optional[str]:
    """
    Extract IP address from threat indicator
    Searches multiple possible fields
    Returns None if no valid IP found
    """
    # Try common IP field names
    possible_fields = [
        'ip', 'IP', 'ip_address', 'ipAddress',
        'indicator', 'value', 'content'
    ]
    
    for field in possible_fields:
        if field in indicator:
            ip_value = str(indicator[field])
            if is_valid_ip(ip_value):
                return ip_value
    
    return None


def categorize_threat(threat: Dict[str, Any], summary: str = "") -> Optional[str]:
    """
    Categorize threat based on tags and type
    Returns None if category cannot be determined
    
    Note: This is ONLY for internal classification
    Final output uses Risk Category (Low/Medium/High) based on score
    """
    # Extract tags
    tags = []
    if 'tags' in threat and isinstance(threat['tags'], list):
        tags = [str(t).lower() for t in threat['tags']]
    
    # Add type to tags for matching
    if 'type' in threat:
        tags.append(str(threat['type']).lower())
    
    # Add summary keywords
    summary_lower = summary.lower()
    tags.append(summary_lower)
    
    # Match against known patterns
    all_text = ' '.join(tags)
    
    if re.search(r'phish|credential|spoof|email', all_text):
        return 'Phishing'
    elif re.search(r'ransom|crypto.*lock|locker', all_text):
        return 'Ransomware'
    elif re.search(r'malware|trojan|virus|worm|botnet|rat', all_text):
        return 'Malware'
    elif re.search(r'ddos|denial.*service|flood|amplification', all_text):
        return 'DDoS'
    elif re.search(r'exploit|vulnerab|cve|rce|injection', all_text):
        return 'Vulnerability Exploits'
    
    return None


def calculate_risk_score(threat: Dict[str, Any]) -> int:
    """
    Calculate normalized risk score (0-100)
    Uses multiple factors: confidence, severity, pulse count
    """
    score = 50  # Default medium score
    
    # Factor 1: Confidence from pulse info
    if 'pulse_info' in threat and threat['pulse_info']:
        pulses = threat['pulse_info'].get('pulses', [])
        if pulses and len(pulses) > 0:
            # More pulses = higher threat
            score += min(len(pulses) * 5, 30)
            
            # Check pulse confidence
            for pulse in pulses[:3]:  # Check first 3 pulses
                confidence = pulse.get('confidence', 50)
                if confidence >= 80:
                    score += 10
    
    # Factor 2: Threat type severity
    threat_type = str(threat.get('type', '')).lower()
    if 'ransomware' in threat_type or 'botnet' in threat_type:
        score += 20
    elif 'malware' in threat_type or 'exploit' in threat_type:
        score += 15
    elif 'phishing' in threat_type:
        score += 10
    
    # Factor 3: Tags severity
    tags = threat.get('tags', [])
    high_severity_tags = ['ransomware', 'apt', 'targeted', 'zero-day', 'critical']
    for tag in tags:
        if any(sev in str(tag).lower() for sev in high_severity_tags):
            score += 5
    
    # Normalize to 0-100
    score = max(0, min(100, score))
    
    return score


def get_risk_category(score: int) -> str:
    """
    MANDATORY: Convert score to Risk Category
    Low → score < 50
    Medium → score 50–74
    High → score ≥ 75
    """
    if score < 50:
        return "Low"
    elif score < 75:
        return "Medium"
    else:
        return "High"


def generate_summary(threat: Dict[str, Any], category: Optional[str], ip: str) -> str:
    """
    Generate user-friendly summary with recommended action
    """
    # Get threat description
    desc = threat.get('description', threat.get('title', ''))
    if not desc:
        desc = f"{category or 'Threat'} activity detected"
    
    # Truncate if too long
    if len(desc) > 100:
        desc = desc[:97] + "..."
    
    # Add recommended action based on category
    actions = {
        'Phishing': 'Block this IP and warn users about suspicious emails.',
        'Ransomware': 'URGENT: Block immediately and check for infections.',
        'Malware': 'Block this IP and scan systems for malicious software.',
        'DDoS': 'Block to prevent denial of service attacks.',
        'Vulnerability Exploits': 'Block and patch vulnerable systems immediately.'
    }
    
    action = actions.get(category, 'Monitor and consider blocking this IP.')
    
    return f"{desc} | Action: {action}"


def get_threat_type(threat: Dict[str, Any], category: Optional[str]) -> str:
    """
    Determine specific threat type for display
    """
    if category:
        type_mapping = {
            'Phishing': 'Phishing Server',
            'Ransomware': 'Ransomware C2',
            'Malware': 'Malware Host',
            'DDoS': 'DDoS Botnet Node',
            'Vulnerability Exploits': 'Exploit Host'
        }
        return type_mapping.get(category, f"{category} Host")
    
    # Fallback to original type
    return threat.get('type', 'Malicious IP')


def process_threat(threat: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process single threat according to strict rules
    Returns None if threat should be discarded
    Returns normalized threat dict if valid
    """
    # RULE 1: Extract IP address (MANDATORY)
    ip_address = extract_ip_from_indicator(threat)
    
    if not ip_address:
        # No valid IP → DISCARD
        return None
    
    # RULE 2: Determine internal category (for summary generation)
    summary_text = threat.get('description', threat.get('title', ''))
    category = categorize_threat(threat, summary_text)
    
    # If no recognizable category, assign generic but still process
    # (We don't discard anymore, we just use Risk Category)
    
    # RULE 3: Calculate risk score
    score = calculate_risk_score(threat)
    
    # RULE 4: Determine Risk Category (MANDATORY OUTPUT)
    risk_category = get_risk_category(score)
    
    # RULE 5: Generate user-friendly summary
    summary = generate_summary(threat, category, ip_address)
    
    # RULE 6: Get threat type
    threat_type = get_threat_type(threat, category)
    
    # RULE 7: Get detection timestamp
    timestamp = threat.get('created', threat.get('modified', threat.get('timestamp', '')))
    if not timestamp:
        timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # RULE 8: Build normalized output (ONLY REQUIRED FIELDS)
    normalized = {
        "Risk Category": risk_category,          # Low / Medium / High
        "Indicator": threat.get('indicator', ip_address),
        "IP Address": ip_address,                 # MANDATORY
        "Type": threat_type,
        "Summary": summary,
        "Score": score,                           # 0-100
        "Detected When": timestamp
    }
    
    return normalized


def filter_and_normalize_threats(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Process list of threats according to strict rules
    
    Returns:
        List of normalized threats (only IP-based, valid threats)
        Empty list if no valid threats found
    """
    processed = []
    seen_ips = set()
    
    for threat in threats:
        # Process threat
        normalized = process_threat(threat)
        
        if normalized:
            ip = normalized['IP Address']
            
            # RULE: Remove duplicates (same IP)
            if ip not in seen_ips:
                seen_ips.add(ip)
                processed.append(normalized)
    
    # Sort by score (highest risk first)
    processed.sort(key=lambda x: x['Score'], reverse=True)
    
    return processed


def validate_output(threat: Dict[str, Any]) -> bool:
    """
    Validate that output has all required fields
    """
    required_fields = [
        "Risk Category",
        "Indicator",
        "IP Address",
        "Type",
        "Summary",
        "Score",
        "Detected When"
    ]
    
    for field in required_fields:
        if field not in threat:
            return False
    
    # Validate Risk Category values
    if threat["Risk Category"] not in ["Low", "Medium", "High"]:
        return False
    
    # Validate Score range
    if not (0 <= threat["Score"] <= 100):
        return False
    
    # Validate IP
    if not is_valid_ip(threat["IP Address"]):
        return False
    
    return True


def get_threats_by_risk(threats: List[Dict[str, Any]], risk_level: str) -> List[Dict[str, Any]]:
    """
    Filter threats by risk category
    
    Args:
        threats: List of processed threats
        risk_level: "Low", "Medium", or "High"
    
    Returns:
        Filtered list of threats
    """
    return [t for t in threats if t.get("Risk Category") == risk_level]


def get_high_risk_ips(threats: List[Dict[str, Any]]) -> List[str]:
    """
    Extract list of high-risk IPs for auto-blocking
    
    Args:
        threats: List of processed threats
    
    Returns:
        List of IP addresses with High risk
    """
    high_risk = get_threats_by_risk(threats, "High")
    return [t["IP Address"] for t in high_risk]


# Statistics and reporting functions
def get_threat_stats(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate statistics about processed threats
    """
    total = len(threats)
    
    if total == 0:
        return {
            "total": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "average_score": 0
        }
    
    low = len(get_threats_by_risk(threats, "Low"))
    medium = len(get_threats_by_risk(threats, "Medium"))
    high = len(get_threats_by_risk(threats, "High"))
    
    avg_score = sum(t["Score"] for t in threats) / total
    
    return {
        "total": total,
        "low": low,
        "medium": medium,
        "high": high,
        "average_score": round(avg_score, 2),
        "unique_ips": len(set(t["IP Address"] for t in threats))
    }
