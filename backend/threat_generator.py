"""
Synthetic Threat Generator for Admin Dashboard
Generates fresh, unique threats on every request with balanced distribution.
"""
import random
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Set
import hashlib

# Threat categories with realistic distribution weights
THREAT_CATEGORIES = {
    "Malware": 0.20,
    "Phishing": 0.20,
    "Ransomware": 0.15,
    "DDoS Attacks": 0.15,
    "Botnet": 0.15,
    "Vulnerability Exploits": 0.15,
}

# Threat types by category for variety
THREAT_TYPES = {
    "Malware": [
        "Trojan.GenericKD", "Backdoor.Agent", "Spyware.KeyLogger", 
        "Adware.Generic", "Rootkit.ZAccess", "Worm.AutoRun"
    ],
    "Phishing": [
        "Phishing.Email", "Credential.Harvesting", "Fake.Login.Page",
        "SMS.Phishing", "Voice.Phishing", "Social.Engineering"
    ],
    "Ransomware": [
        "Ransomware.LockBit", "Crypto.Locker", "WannaCry.Variant",
        "Ryuk.Ransomware", "Maze.Ransomware", "REvil.Ransomware"
    ],
    "DDoS Attacks": [
        "DDoS.UDP.Flood", "SYN.Flood.Attack", "HTTP.Flood",
        "DNS.Amplification", "NTP.Amplification", "ICMP.Flood"
    ],
    "Botnet": [
        "Botnet.Mirai", "Botnet.Zeus", "Botnet.Emotet",
        "Botnet.TrickBot", "Botnet.Qakbot", "Botnet.IcedID"
    ],
    "Vulnerability Exploits": [
        "CVE-2024-Critical", "Zero.Day.Exploit", "SQL.Injection",
        "RCE.Exploit", "Privilege.Escalation", "Buffer.Overflow"
    ],
}

# Status types
STATUS_TYPES = ["Active", "Detected", "Monitoring", "Analyzing", "Investigating"]

# Global registry of used IPs to ensure uniqueness across all sessions
_used_ips_registry: Set[str] = set()
_session_counter = 0


def _generate_unique_ip(excluded_ips: Set[str]) -> str:
    """
    Generate a unique public IP address that hasn't been used before.
    Excludes private ranges and already used IPs.
    """
    max_attempts = 1000
    
    for _ in range(max_attempts):
        # Generate random public IP (avoid private ranges)
        # Public IP ranges: avoid 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x
        octets = []
        
        # First octet: avoid 10, 127, 172, 192, 169
        first = random.choice([i for i in range(1, 224) if i not in [10, 127, 172, 192, 169, 0]])
        octets.append(first)
        
        # Second octet
        if first == 172:
            # Avoid 172.16.x.x to 172.31.x.x
            second = random.choice([i for i in range(256) if i < 16 or i > 31])
        else:
            second = random.randint(0, 255)
        octets.append(second)
        
        # Third and fourth octets
        octets.append(random.randint(0, 255))
        octets.append(random.randint(1, 254))  # Avoid .0 and .255
        
        ip = ".".join(map(str, octets))
        
        # Verify it's a valid public IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                continue
        except:
            continue
        
        # Check if already used
        if ip not in excluded_ips and ip not in _used_ips_registry:
            _used_ips_registry.add(ip)
            return ip
    
    # Fallback: generate from hash to ensure uniqueness
    seed = f"{datetime.utcnow().isoformat()}-{random.random()}-{len(_used_ips_registry)}"
    hash_val = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16)
    
    # Create IP from hash
    octets = [
        (hash_val >> 24) % 224 + 1,  # First octet: 1-224
        (hash_val >> 16) % 256,
        (hash_val >> 8) % 256,
        hash_val % 254 + 1,  # Last octet: 1-254
    ]
    
    ip = ".".join(map(str, octets))
    _used_ips_registry.add(ip)
    return ip


def _calculate_threat_score(severity: str, category: str) -> float:
    """
    Calculate threat score based on severity with some randomness.
    Low: <50, Medium: 51-74, High: 75-100
    """
    if severity == "High":
        base = random.uniform(75, 95)
    elif severity == "Medium":
        base = random.uniform(51, 74)
    else:  # Low
        base = random.uniform(25, 49)
    
    # Add category-specific adjustments
    category_boost = {
        "Ransomware": 5,
        "Vulnerability Exploits": 3,
        "DDoS Attacks": 2,
        "Botnet": 2,
        "Malware": 1,
        "Phishing": 0,
    }
    
    score = base + category_boost.get(category, 0)
    return round(min(100, max(0, score)), 2)


def _generate_detection_time() -> str:
    """Generate realistic detection time (within last 24 hours)."""
    now = datetime.utcnow()
    # Random time within last 24 hours
    hours_ago = random.uniform(0, 24)
    detection_time = now - timedelta(hours=hours_ago)
    return detection_time.isoformat() + "Z"


def generate_fresh_threats(count: int = 15, excluded_ips: Set[str] = None) -> List[Dict]:
    """
    Generate a fresh set of synthetic threats with:
    - Unique IP addresses (never repeated)
    - Balanced severity distribution (equal Low, Medium, High)
    - Balanced category distribution
    - Realistic threat data
    
    Args:
        count: Number of threats to generate (default 15)
        excluded_ips: Set of IPs to exclude (optional)
    
    Returns:
        List of threat dictionaries
    """
    global _session_counter
    _session_counter += 1
    
    if excluded_ips is None:
        excluded_ips = set()
    
    # Ensure count is divisible by 3 for equal severity distribution
    if count % 3 != 0:
        count = (count // 3 + 1) * 3
    
    threats_per_severity = count // 3
    
    # Calculate threats per category (equal distribution)
    categories = list(THREAT_CATEGORIES.keys())
    threats_per_category = count // len(categories)
    extra_threats = count % len(categories)
    
    threats = []
    used_ips = set(excluded_ips)
    
    # Generate threats with balanced distribution
    severity_order = (
        ["High"] * threats_per_severity +
        ["Medium"] * threats_per_severity +
        ["Low"] * threats_per_severity
    )
    
    # Shuffle to randomize order
    random.shuffle(severity_order)
    
    # Track category usage for balanced distribution
    category_counts = {cat: 0 for cat in categories}
    
    for idx, severity in enumerate(severity_order):
        # Select category with least usage (round-robin with randomness)
        available_categories = [
            cat for cat in categories
            if category_counts[cat] < threats_per_category + (1 if category_counts[cat] < extra_threats else 0)
        ]
        
        if not available_categories:
            available_categories = categories
        
        category = random.choice(available_categories)
        category_counts[category] += 1
        
        # Generate unique IP
        ip_address = _generate_unique_ip(used_ips)
        used_ips.add(ip_address)
        
        # Get threat type
        threat_type = random.choice(THREAT_TYPES[category])
        
        # Calculate score based on severity
        score = _calculate_threat_score(severity, category)
        
        # Generate detection time
        detection_time = _generate_detection_time()
        
        # Select status
        status = random.choice(STATUS_TYPES)
        
        # Create threat object
        threat = {
            "id": f"THR-{_session_counter:04d}-{idx+1:03d}",
            "indicator": ip_address,
            "ip": ip_address,  # Alias for compatibility
            "category": category,
            "type": threat_type,
            "score": score,
            "severity": severity,
            "threat_level": severity,  # Alias for compatibility
            "detection_time": detection_time,
            "first_seen": detection_time,
            "last_seen": detection_time,
            "status": status,
            "summary": f"{threat_type} detected from {ip_address}",
            "pulse_count": random.randint(1, 50),
            "reputation": round(1 - (score / 100), 2),  # Higher score = lower reputation
            "source": "synthetic",
            "otx_id": f"synthetic-{hashlib.md5(ip_address.encode()).hexdigest()}",
        }
        
        threats.append(threat)
    
    # Final shuffle for randomness
    random.shuffle(threats)
    
    print(f"\n[THREAT GENERATOR] Generated {len(threats)} fresh threats:")
    print(f"  - High: {len([t for t in threats if t['severity'] == 'High'])}")
    print(f"  - Medium: {len([t for t in threats if t['severity'] == 'Medium'])}")
    print(f"  - Low: {len([t for t in threats if t['severity'] == 'Low'])}")
    print(f"  - Categories: {dict(category_counts)}")
    print(f"  - Sample IPs: {[t['ip'] for t in threats[:3]]}")
    print(f"  - Total unique IPs in registry: {len(_used_ips_registry)}")
    
    return threats


def clear_ip_registry():
    """Clear the IP registry (use with caution - for testing only)."""
    global _used_ips_registry, _session_counter
    _used_ips_registry.clear()
    _session_counter = 0
    print("[THREAT GENERATOR] IP registry cleared")


def get_registry_stats() -> Dict:
    """Get statistics about the IP registry."""
    return {
        "total_unique_ips": len(_used_ips_registry),
        "session_counter": _session_counter,
        "sample_ips": list(_used_ips_registry)[:10] if _used_ips_registry else []
    }


# Test function
if __name__ == "__main__":
    print("=" * 80)
    print("THREAT GENERATOR TEST")
    print("=" * 80)
    
    # Generate first batch
    print("\n--- Batch 1 ---")
    threats1 = generate_fresh_threats(15)
    
    # Generate second batch (should have completely different IPs)
    print("\n--- Batch 2 ---")
    threats2 = generate_fresh_threats(15)
    
    # Verify no IP overlap
    ips1 = set(t['ip'] for t in threats1)
    ips2 = set(t['ip'] for t in threats2)
    overlap = ips1 & ips2
    
    print(f"\n--- Verification ---")
    print(f"Batch 1 IPs: {len(ips1)}")
    print(f"Batch 2 IPs: {len(ips2)}")
    print(f"Overlap: {len(overlap)}")
    print(f"✅ All IPs unique!" if not overlap else f"❌ Found {len(overlap)} duplicate IPs: {overlap}")
    
    # Show stats
    print(f"\n--- Registry Stats ---")
    stats = get_registry_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
