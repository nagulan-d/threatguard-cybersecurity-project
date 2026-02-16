# IP Blocking Synchronization - Quick Reference Guide

## 🚀 Quick Start

### 1. Windows Setup (5 minutes)
```powershell
# Run as Administrator
cd Final_Project
.\SETUP_BLOCKING_SYNC.ps1
```

### 2. Kali/Linux Setup (5 minutes)
```bash
# On Kali VM
chmod +x backend/vm_agent/SETUP_BLOCKING_AGENT.sh
./backend/vm_agent/SETUP_BLOCKING_AGENT.sh

# Start service
sudo systemctl start threatguard-agent
```

### 3. Verify Systems Online
```bash
# Test Windows → Linux connectivity
curl http://192.168.1.100:5001/api/health

# Test both systems health
curl http://localhost:5000/api/blocking/health
```

---

## 🔗 API Quick Reference

### Block an IP
```bash
curl -X POST http://localhost:5000/api/blocking/block \
  -H "Authorization: Bearer <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.0.2.1",
    "threat_category": "Ransomware",
    "risk_score": 95,
    "reason": "Detected C2 communication"
  }'
```

### Unblock an IP
```bash
curl -X POST http://localhost:5000/api/blocking/unblock \
  -H "Authorization: Bearer <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.0.2.1"}'
```

### Get Blocking Status
```bash
curl "http://localhost:5000/api/blocking/status/192.0.2.1?token=<API_TOKEN>"
```

### List All Blocked IPs (Admin)
```bash
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:5000/api/blocking/list
```

### Get System Health
```bash
curl http://localhost:5000/api/blocking/health
```

---

## 🐍 Python Code Examples

### Block IP Programmatically
```python
from windows_blocking_coordinator import coordinator

result = coordinator.block_threat_ip(
    ip_address="192.0.2.1",
    threat_info={
        "category": "Phishing",
        "risk_score": 85,
        "reason": "Phishing server detected"
    },
    user=current_user,
    allow_partial_block=False
)

if result["status"] == "completed":
    print(f"✅ Successfully blocked on both systems")
elif result["status"] == "partial":
    print(f"⚠️  Partially blocked")
else:
    print(f"❌ Blocking failed: {result['errors']}")
```

### Auto-Block High-Risk Threats
```python
# In threat detection code
if threat['risk_score'] > 90:
    result = coordinator.auto_block_high_risk_threat(
        ip_address=threat['ip'],
        threat_info=threat
    )
```

### Check System Health
```python
from health_monitoring import health_check_service

health = health_check_service.get_current_health()
if health["overall"] == "healthy":
    print("✅ Both systems operational")
else:
    print(f"⚠️  System degraded: {health}")
```

### Validate Blocking Consistency
```python
from blocking_rules_validator import sync_validator

result = sync_validator.validate_sync("192.0.2.1")
if result["consistent"]:
    print("✅ Blocking consistent across systems")
else:
    print(f"❌ Issues found: {result['issues']}")
```

---

## 🔍 Monitoring Commands

### Windows Firewall

```powershell
# List all ThreatGuard rules
netsh advfirewall firewall show rule name="TG_BLOCK*"

# Count active rules
(netsh advfirewall firewall show rule name="TG_BLOCK*" | Measure-Object).Count

# Check specific IP
netsh advfirewall firewall show rule name="TG_BLOCK_192_0_2_1*"

# Delete a rule (cleanup if needed)
netsh advfirewall firewall delete rule name="TG_BLOCK_192_0_2_1_IN"
```

### Linux iptables

```bash
# List THREATGUARD chain
sudo iptables -L THREATGUARD -n -v

# Count blocked IPs
sudo iptables -L THREATGUARD -n | grep DROP | wc -l

# Check specific IP
sudo iptables -C THREATGUARD -s 192.0.2.1 -j DROP

# Count rules
sudo iptables -L THREATGUARD | wc -l
```

### Kali Agent

```bash
# View logs
tail -f /opt/threatguard/logs/blocking_agent.log

# Check service status
sudo systemctl status threatguard-agent

# View blocked IPs on agent
curl -H "Authorization: Bearer <TOKEN>" http://localhost:5001/api/blocking/list

# Check health
curl http://localhost:5001/api/health
```

---

## 🚨 Emergency Procedures

### Clear All Blocks (Emergency)
```python
# Python
from windows_blocking_coordinator import coordinator

blocked_ips = coordinator.get_blocked_ips_list()
for ip_info in blocked_ips:
    coordinator.unblock_threat_ip(ip_info['ip'])
print(f"✅ Cleared {len(blocked_ips)} blocked IPs")
```

### Restart Windows Firewall
```powershell
# Windows
net stop MpsSvc
net start MpsSvc
echo "✅ Windows Firewall restarted"
```

### Restart Linux Agent
```bash
# Linux
sudo systemctl restart threatguard-agent
sudo systemctl status threatguard-agent
```

### Purge All Rules (Last Resort)
```bash
# Windows
netsh advfirewall firewall delete rule name="TG_BLOCK*"

# Linux
sudo iptables -F THREATGUARD
sudo iptables -X THREATGUARD
```

---

## 🧪 Test Cases

### Test 1: Block an IP
```bash
# Block
curl -X POST http://localhost:5000/api/blocking/block \
  -H "Authorization: Bearer $(echo $BLOCKING_API_TOKEN)" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "203.0.113.15", "threat_category": "Test", "risk_score": 50}'

# Verify Windows
netsh advfirewall firewall show rule name="TG_BLOCK_203_0_113_15*"

# Verify Linux
sudo iptables -C THREATGUARD -s 203.0.113.15 -j DROP && echo "✅ Found"
```

### Test 2: Unblock an IP
```bash
# Unblock
curl -X POST http://localhost:5000/api/blocking/unblock \
  -H "Authorization: Bearer $BLOCKING_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "203.0.113.15"}'

# Verify Windows (should return no rules)
netsh advfirewall firewall show rule name="TG_BLOCK_203_0_113_15*"

# Verify Linux (should fail)
sudo iptables -C THREATGUARD -s 203.0.113.15 -j DROP && echo "❌ Still blocked" || echo "✅ Unblocked"
```

### Test 3: Sync Consistency
```bash
# Block an IP via API
curl -X POST http://localhost:5000/api/blocking/block \
  -H "Authorization: Bearer $BLOCKING_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "203.0.113.20", "threat_category": "Test"}'

# Wait 2 seconds
sleep 2

# Validate consistency
python3 << 'EOF'
from blocking_rules_validator import sync_validator
result = sync_validator.validate_sync("203.0.113.20")
print(f"Consistent: {result['consistent']}")
print(f"Windows: {result['windows']['exists']}")
print(f"Linux: {result['linux']['exists']}")
if result['issues']:
    print(f"Issues: {result['issues']}")
EOF
```

---

## 📊 Database Queries

### View Recent Blocking Operations
```sql
SELECT 
    ip_address,
    action,
    windows_status,
    linux_status,
    sync_status,
    initiated_at
FROM blocking_sync_record
ORDER BY initiated_at DESC
LIMIT 20;
```

### View Sync Logs
```sql
SELECT 
    ip_address,
    action,
    component,
    message,
    status,
    timestamp
FROM sync_log
WHERE timestamp > datetime('now', '-1 hour')
ORDER BY timestamp DESC;
```

### Blocking Statistics
```sql
SELECT 
    COUNT(*) as total_blocks,
    SUM(CASE WHEN sync_status = 'completed' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN sync_status = 'failed' THEN 1 ELSE 0 END) as failed,
    ROUND(AVG(risk_score), 2) as avg_risk_score
FROM blocking_sync_record
WHERE action = 'block';
```

---

## 🔐 Token Management

### Generate New API Token
```python
import secrets
new_token = secrets.token_urlsafe(32)
print(f"New API token: {new_token}")
```

### Update Token in .env
```bash
# Windows
# Add or update in backend/.env
BLOCKING_API_TOKEN=new_token_here

# Linux
# Update service environment
sudo systemctl edit threatguard-agent
# Change: Environment="BLOCKING_API_TOKEN=new_token_here"
sudo systemctl restart threatguard-agent
```

---

## 📈 Performance Tuning

### Optimize Health Check Interval
```python
# In app.py during initialization
from health_monitoring import health_check_service

# More frequent checks (aggressive)
health_check_service.check_interval = 30  # 30 seconds

# Less frequent checks (conservative)
health_check_service.check_interval = 120  # 2 minutes
```

### Increase Retry Attempts
```python
# In SyncConfig
config.max_retry_attempts = 5
config.retry_interval_seconds = 60
```

---

## 🐛 Debug Mode

### Enable Debug Logging
```python
# In app.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Enable Agent Debug Mode
```bash
# On Kali VM
export DEBUG=true
python3 /opt/threatguard/enhanced_blocking_agent.py
```

### View Detailed Logs
```bash
# Windows
type backend\logs\backend_debug.log | tail -50

# Linux
journalctl -u threatguard-agent -n 100 --no-pager
```

---

## 📞 Troubleshooting

| Issue | Solution |
|-------|----------|
| Agent not responding | Check: `sudo systemctl status threatguard-agent` |
| Duplicate rules | Run: `python3 -c "from blocking_rules_validator import sync_validator; sync_validator.validate_all_blocks()"` |
| Partial blocking | Check health: `curl localhost:5000/api/blocking/health` |
| Token rejected | Verify token matches in Windows and Linux |
| Rules not applying | Check: `netsh advfirewall show allprofiles` and `sudo iptables -L` |

---

**Last Updated**: 2026-02-15  
**Quick Reference Version**: 1.0

For detailed documentation, see `IP_BLOCKING_SYNC_IMPLEMENTATION.md`
