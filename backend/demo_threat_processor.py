"""
Demonstration: CTI Processing with Strict Rules
Shows how to use threat_processor for real-world threat intelligence
"""

from threat_processor import (
    filter_and_normalize_threats,
    get_threats_by_risk,
    get_high_risk_ips,
    get_threat_stats
)

print("=" * 80)
print("CTI THREAT PROCESSOR - LIVE DEMONSTRATION")
print("=" * 80)
print()

# Simulate real CTI data from AlienVault OTX or similar platforms
sample_cti_data = [
    # Valid IP-based threats
    {
        "indicator": "45.142.212.100",
        "type": "IPv4",
        "tags": ["phishing", "credential-stealer", "malicious-email"],
        "description": "Phishing server impersonating major bank login pages",
        "created": "2026-01-02T10:30:00Z",
        "pulse_info": {
            "pulses": [
                {"name": "Banking Phishing Campaign", "confidence": 85},
                {"name": "Credential Theft Infrastructure", "confidence": 90}
            ]
        }
    },
    {
        "indicator": "185.220.101.5",
        "type": "IPv4",
        "tags": ["ransomware", "lockbit", "crypto-locker"],
        "description": "LockBit ransomware command and control server",
        "created": "2026-01-02T09:15:00Z",
        "pulse_info": {
            "pulses": [
                {"name": "LockBit 3.0 Infrastructure", "confidence": 95},
                {"name": "Ransomware C2", "confidence": 92}
            ]
        }
    },
    {
        "indicator": "103.109.247.12",
        "type": "IPv4",
        "tags": ["ddos", "botnet", "mirai", "iot"],
        "description": "Mirai botnet node participating in DDoS attacks",
        "created": "2026-01-01T18:45:00Z",
        "pulse_info": {
            "pulses": [
                {"name": "Mirai Botnet Wave", "confidence": 80}
            ]
        }
    },
    {
        "indicator": "198.51.100.25",
        "type": "IPv4",
        "tags": ["exploit", "cve-2024-1234", "rce"],
        "description": "Actively exploiting CVE-2024-1234 remote code execution vulnerability",
        "created": "2026-01-02T11:00:00Z",
        "pulse_info": {
            "pulses": [
                {"name": "Zero-Day Exploitation", "confidence": 88}
            ]
        }
    },
    {
        "indicator": "23.95.67.200",
        "type": "IPv4",
        "tags": ["malware", "trojan", "info-stealer"],
        "description": "Trojan malware distribution server",
        "created": "2026-01-01T14:20:00Z",
        "pulse_info": {
            "pulses": [
                {"name": "Info Stealer Campaign", "confidence": 75}
            ]
        }
    },
    
    # Invalid threats that will be REJECTED
    {
        "indicator": "malware.exe",
        "type": "file_hash",
        "hash": "d41d8cd98f00b204e9800998ecf8427e",
        "tags": ["malware", "trojan"],
        "description": "Malicious executable detected"
        # NO IP → REJECTED
    },
    {
        "indicator": "evil.com",
        "type": "domain",
        "tags": ["phishing"],
        "description": "Phishing domain"
        # NO IP → REJECTED
    },
    {
        "indicator": "192.168.1.100",
        "type": "IPv4",
        "tags": ["unknown", "misc"],
        "description": "Unclassified traffic"
        # Valid IP but will still be processed (no longer rejected)
    }
]

print("📥 STEP 1: Fetching CTI Data")
print("-" * 80)
print(f"Total raw indicators fetched: {len(sample_cti_data)}")
print()

print("🔍 STEP 2: Processing with Strict Rules")
print("-" * 80)
print("✓ Validating IP addresses (rejecting null, N/A, hashes)")
print("✓ Calculating risk scores (0-100)")
print("✓ Categorizing as Low / Medium / High")
print("✓ Removing duplicates")
print("✓ Normalizing output format")
print()

# Process threats
processed_threats = filter_and_normalize_threats(sample_cti_data)

print("📊 STEP 3: Processing Results")
print("-" * 80)
print(f"✅ Accepted (IP-based): {len(processed_threats)}")
print(f"❌ Rejected (no IP/hash-only): {len(sample_cti_data) - len(processed_threats)}")
print()

# Get statistics
stats = get_threat_stats(processed_threats)
print("📈 STEP 4: Threat Statistics")
print("-" * 80)
print(f"Total Threats: {stats['total']}")
print(f"  🟢 Low Risk: {stats['low']}")
print(f"  🟡 Medium Risk: {stats['medium']}")
print(f"  🔴 High Risk: {stats['high']}")
print(f"Average Score: {stats['average_score']}")
print(f"Unique IPs: {stats['unique_ips']}")
print()

# Show high-risk threats
print("🚨 STEP 5: High-Risk Threats (Auto-Block Candidates)")
print("-" * 80)
high_risk = get_threats_by_risk(processed_threats, "High")
if high_risk:
    for threat in high_risk:
        print(f"⚠️  IP: {threat['IP Address']}")
        print(f"   Type: {threat['Type']}")
        print(f"   Score: {threat['Score']}/100")
        print(f"   Summary: {threat['Summary'][:100]}...")
        print()
else:
    print("No high-risk threats detected")
print()

# Show medium-risk threats
print("⚠️  STEP 6: Medium-Risk Threats (Monitor)")
print("-" * 80)
medium_risk = get_threats_by_risk(processed_threats, "Medium")
if medium_risk:
    for threat in medium_risk:
        print(f"📍 IP: {threat['IP Address']}")
        print(f"   Type: {threat['Type']}")
        print(f"   Score: {threat['Score']}/100")
        print()
else:
    print("No medium-risk threats detected")
print()

# Get IPs for auto-blocking
print("🔒 STEP 7: IP Auto-Blocking List")
print("-" * 80)
high_risk_ips = get_high_risk_ips(processed_threats)
if high_risk_ips:
    print(f"IPs recommended for immediate blocking: {len(high_risk_ips)}")
    for ip in high_risk_ips:
        print(f"  → {ip}")
else:
    print("No IPs require immediate blocking")
print()

# Show final dashboard-ready output
print("📋 STEP 8: Dashboard-Ready Output (First 3 Threats)")
print("-" * 80)
for i, threat in enumerate(processed_threats[:3], 1):
    print(f"\nThreat #{i}:")
    for key, value in threat.items():
        if key == "Summary":
            print(f"  {key}: {value[:80]}...")
        else:
            print(f"  {key}: {value}")

print()
print("=" * 80)
print("✅ CTI PROCESSING COMPLETE")
print("=" * 80)
print()
print("🎯 WHAT THIS DEMONSTRATES:")
print("  ✓ Only IP-based threats are accepted")
print("  ✓ File hashes and domains without IPs are rejected")
print("  ✓ Risk categorization is based on score (Low/Medium/High)")
print("  ✓ Output is clean, normalized, and dashboard-ready")
print("  ✓ High-risk IPs can be extracted for auto-blocking")
print("  ✓ All output fields are consistent and required")
print()
print("🚀 READY FOR:")
print("  → Admin dashboard display")
print("  → Automatic IP blocking integration")
print("  → User notifications")
print("  → Security automation workflows")
print()
