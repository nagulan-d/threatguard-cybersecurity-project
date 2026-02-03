"""
QUICK REFERENCE: Threat Processor Usage
========================================

BASIC USAGE
-----------
from threat_processor import filter_and_normalize_threats

# Process raw CTI data
processed = filter_and_normalize_threats(raw_threats)

# Result: Clean, IP-based threats only


GET BY RISK LEVEL
-----------------
from threat_processor import get_threats_by_risk

high = get_threats_by_risk(processed, "High")
medium = get_threats_by_risk(processed, "Medium")
low = get_threats_by_risk(processed, "Low")


AUTO-BLOCKING
-------------
from threat_processor import get_high_risk_ips

# Get IPs to block
dangerous_ips = get_high_risk_ips(processed)

# Block them
for ip in dangerous_ips:
    ip_blocker.block_ip(ip, "High-risk CTI threat")


STATISTICS
----------
from threat_processor import get_threat_stats

stats = get_threat_stats(processed)
# {
#   "total": 10,
#   "low": 2,
#   "medium": 5,
#   "high": 3,
#   "average_score": 65.5,
#   "unique_ips": 10
# }


VALIDATION
----------
from threat_processor import is_valid_ip

is_valid_ip("192.168.1.1")   # True
is_valid_ip("999.1.1.1")     # False
is_valid_ip("null")          # False


OUTPUT FORMAT
-------------
{
    "Risk Category": "High",             # Low | Medium | High
    "Indicator": "185.220.101.5",
    "IP Address": "185.220.101.5",       # MANDATORY
    "Type": "Ransomware C2",
    "Summary": "LockBit ransomware...",
    "Score": 85,                         # 0-100
    "Detected When": "2026-01-02T09:15:00Z"
}


ACCEPTANCE RULES
----------------
✅ ACCEPTED:
  • Valid IPv4 or IPv6 address present
  • Calculable risk score
  • Any threat with IP

❌ REJECTED:
  • No IP address (null, N/A, missing)
  • File hash only (MD5, SHA1, SHA256)
  • Domain without IP


RISK SCORING
------------
Low Risk     → Score < 50
Medium Risk  → Score 50-74
High Risk    → Score ≥ 75

Score factors:
  • Pulse confidence (+10-30)
  • Threat type severity (+10-20)
  • Critical tags (+5 each)
  • Base score: 50


INTEGRATION EXAMPLE
-------------------
# 1. Fetch CTI data
raw = fetch_from_otx()

# 2. Process
threats = filter_and_normalize_threats(raw)

# 3. Auto-block high-risk
for ip in get_high_risk_ips(threats):
    block_ip(ip)

# 4. Notify users
high = get_threats_by_risk(threats, "High")
for threat in high:
    notify_user(threat)

# 5. Display on dashboard
return jsonify(threats)


TESTING
-------
# Run tests
python test_threat_processor.py

# Run demo
python demo_threat_processor.py


PERFORMANCE
-----------
Processing: ~1000 threats/second
Memory: Minimal overhead
Duplicate removal: O(n)
"""
