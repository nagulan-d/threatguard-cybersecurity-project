# IP Blocking Synchronization System - Implementation Guide

## Overview

This is a production-grade IP blocking synchronization system that automatically synchronizes firewall rules between:
- **Windows Host** (using Windows Defender Firewall via netsh)
- **Kali Linux VM** (using iptables/ufw)

Real-time communication ensures instant blocking across both systems with centralized logging and health monitoring.

---

## Architecture

### Components

1. **blocking_sync_service.py** - Core synchronization engine
   - Coordinates blocking between Windows and Linux
   - Manages retry logic and partial failures
   - Maintains centralized database of blocked IPs

2. **windows_blocking_coordinator.py** - Windows-side orchestration
   - Handles manual dashboard blocks
   - Processes auto-blocking of high-risk threats
   - Manages unblocking operations

3. **enhanced_blocking_agent.py** - Kali Linux agent
   - REST API server for receiving blocking commands
   - Local iptables management
   - Persistent storage of blocked IPs

4. **blocking_sync_api.py** - REST API endpoints
   - Secure endpoints for blocking/unblocking
   - Admin dashboard endpoints
   - Health check and monitoring endpoints

5. **websocket_sync.py** - Real-time notifications
   - WebSocket event broadcasting
   - Real-time status updates to admin dashboard
   - Event history and subscriber management

6. **health_monitoring.py** - System health tracking
   - Continuous monitoring of Windows Firewall and Linux agent
   - Health metrics and statistics
   - Alert system for degraded status

7. **blocking_rules_validator.py** - Rule validation and duplicate prevention
   - Validates IP addresses
   - Prevents duplicate rules
   - Ensures sync consistency

---

## Installation & Configuration

### 1. Windows Host Setup

#### Environment Variables (.env)

```env
# Linux/Kali VM Connection
LINUX_VM_HOST=192.168.1.100
LINUX_VM_PORT=22
LINUX_VM_API_PORT=5001
LINUX_VM_API_TOKEN=your_secure_token_here
LINUX_VM_USER=kali

# Blocking Service Configuration
BLOCKING_API_TOKEN=threatguard_sync_token_secret
USE_SSH_BLOCKING=false
SYNC_TIMEOUT=30

# Feature Flags
ENABLE_SYNC=true
AUTO_RETRY_FAILED=true
MAX_RETRY_ATTEMPTS=3
RETRY_INTERVAL_SECONDS=30

# Health Checks
HEALTH_CHECK_INTERVAL=60
HEALTH_CHECK_ENABLED=true

# Admin Token Secret
ADMIN_TOKEN_SECRET=admin_secret_key_change_me
```

#### Database Migration

Add these models to your Flask app and run migrations:

```bash
# In backend directory
flask db migrate -m "Add blocking sync tables"
flask db upgrade
```

#### Initialize Sync Configuration

```python
# In your Flask app initialization
from models import SyncConfig, db

def init_sync_config():
    config = SyncConfig.query.first()
    if not config:
        config = SyncConfig(
            linux_host=os.getenv("LINUX_VM_HOST", "192.168.1.100"),
            linux_port=int(os.getenv("LINUX_VM_PORT", "22")),
            linux_api_port=int(os.getenv("LINUX_VM_API_PORT", "5001")),
            use_api=True,
            enable_sync=True,
            auto_retry_failed=True,
            max_retry_attempts=3,
            block_inbound=True,
            block_outbound=True
        )
        db.session.add(config)
        db.session.commit()
```

### 2. Kali Linux VM Setup

#### Install Requirements

```bash
# SSH into Kali VM
ssh kali@192.168.1.100

# Install Python dependencies
pip install flask requests

# For iptables/ufw management (usually pre-installed)
apt-get update
apt-get install iptables ufw

# Create agent directory
mkdir -p /opt/threatguard
cd /opt/threatguard
```

#### Deploy Enhanced Blocking Agent

```bash
# Copy enhanced_blocking_agent.py to Kali VM
scp backend/vm_agent/enhanced_blocking_agent.py kali@192.168.1.100:/opt/threatguard/

# Make executable
chmod +x /opt/threatguard/enhanced_blocking_agent.py

# Create systemd service file
sudo tee /etc/systemd/system/threatguard-agent.service << EOF
[Unit]
Description=ThreatGuard Blocking Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/threatguard
Environment="BLOCKING_API_TOKEN=your_secure_token_here"
Environment="BLOCKING_AGENT_PORT=5001"
Environment="DEBUG=false"
ExecStart=/usr/bin/python3 /opt/threatguard/enhanced_blocking_agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable threatguard-agent
sudo systemctl start threatguard-agent

# Verify status
sudo systemctl status threatguard-agent
```

#### UFW/IPTables Configuration

```bash
# If using ufw (simpler, recommended)
sudo ufw enable
sudo ufw status

# If using iptables (more control)
# Create THREATGUARD chain
sudo iptables -N THREATGUARD 2>/dev/null || echo "Chain exists"

# Link to INPUT and OUTPUT
sudo iptables -I INPUT -j THREATGUARD
sudo iptables -I OUTPUT -j THREATGUARD

# Save rules (persist across reboot)
sudo apt-get install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
```

---

## Flask App Integration

### 1. Update app.py

```python
# Add these imports at the top of app.py
from blocking_sync_service import blocking_sync_service
from windows_blocking_coordinator import coordinator
from blocking_sync_api import create_blocking_sync_blueprint
from health_monitoring import health_check_service
from websocket_sync import broadcaster, realtime_coordinator

# After app initialization, register the blocking API
blocking_api_bp = create_blocking_sync_blueprint(blocking_sync_service, coordinator)
app.register_blueprint(blocking_api_bp)

# Initialize sync service with app and db
blocking_sync_service.app = app
blocking_sync_service.db = db
coordinator.app = app
coordinator.db = db
coordinator.sync_service = blocking_sync_service

# Initialize health checks
def alert_on_health_degradation(health_check):
    """Alert when system health degrades"""
    logger.warning(f"Health alert: {health_check['overall']}")
    # Could send email notification here

health_check_service.add_alert_callback(alert_on_health_degradation)
```

### 2. Create Database Initialization Script

```python
# backend/init_blocking_sync.py
from app import app, db
from models import SyncConfig

with app.app_context():
    # Check if config exists
    config = SyncConfig.query.first()
    
    if not config:
        print("Initializing sync configuration...")
        config = SyncConfig(
            linux_host="192.168.1.100",
            linux_api_port=5001,
            enable_sync=True,
            auto_retry_failed=True,
            block_inbound=True,
            block_outbound=True
        )
        db.session.add(config)
        db.session.commit()
        print("✅ Sync configuration initialized")
    else:
        print("✅ Sync configuration already exists")
```

---

## API Endpoints

### Blocking Endpoints (Require API Token)

#### Block IP
```bash
POST /api/blocking/block
Authorization: Bearer <BLOCKING_API_TOKEN>
Content-Type: application/json

{
  "ip_address": "192.0.2.1",
  "threat_category": "Ransomware",
  "risk_score": 95.5,
  "reason": "Detected C2 communication",
  "allow_partial_block": false
}
```

#### Unblock IP
```bash
POST /api/blocking/unblock
Authorization: Bearer <BLOCKING_API_TOKEN>
Content-Type: application/json

{
  "ip_address": "192.0.2.1"
}
```

#### Get Blocking Status
```bash
GET /api/blocking/status/192.0.2.1?token=<BLOCKING_API_TOKEN>
```

### Admin Endpoints (Require Auth)

#### List Blocked IPs
```bash
GET /api/blocking/list
Authorization: Bearer <JWT_TOKEN>
```

#### Get Blocking History
```bash
GET /api/blocking/history/192.0.2.1?limit=20
Authorization: Bearer <JWT_TOKEN>
```

#### Get Statistics
```bash
GET /api/blocking/statistics
Authorization: Bearer <JWT_TOKEN>
```

#### Health Check
```bash
GET /api/blocking/health
```

#### Verify Connectivity
```bash
GET /api/blocking/verify-connectivity
Authorization: Bearer <JWT_TOKEN>
```

---

## WebSocket Integration

### Automatic Event Broadcasting

When blocking operations occur, events are automatically broadcast to connected WebSocket clients:

```javascript
// Frontend example
const ws = new WebSocket('ws://localhost:5000/ws/blocking-sync');

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  
  if (message.type === 'blocking_event') {
    console.log(`IP ${message.data.ip}: ${message.event_type}`);
    // Update admin dashboard UI
  }
};
```

### Event Types

- `block_initiated` - Blocking started
- `block_completed` - Successfully blocked on both systems
- `block_failed` - Both systems failed to block
- `sync_status_update` - Status update during sync
- `health_status_update` - System health changed
- `error` - Error occurred

---

## Usage Examples

### 1. Automatic Block from Threat Processor

```python
# In your threat detection code
from windows_blocking_coordinator import coordinator

threat_data = {
    "category": "Ransomware",
    "risk_score": 98.7,
    "reason": "High-risk C2 detected"
}

result = coordinator.block_threat_ip(
    ip_address="192.0.2.1",
    threat_info=threat_data,
    user=current_user,
    allow_partial_block=False
)

if result["status"] == "completed":
    print(f"✅ IP blocked on Windows and Linux")
elif result["status"] == "partial":
    print(f"⚠️ IP blocked on {result['windows_status']} (Windows) and {result['linux_status']} (Linux)")
else:
    print(f"❌ Blocking failed: {result['errors']}")
```

### 2. Manual Dashboard Block

```python
# In admin dashboard endpoint
@app.route('/api/admin/block-ip', methods=['POST'])
@login_required
@admin_required
def dashboard_block_ip():
    data = request.get_json()
    
    result = coordinator.block_threat_ip(
        ip_address=data['ip'],
        threat_info={
            "category": data.get('category', 'Manual'),
            "risk_score": data.get('risk_score', 100),
            "reason": data.get('reason', 'Manually blocked by admin')
        },
        user=current_user
    )
    
    return jsonify(result)
```

### 3. Health Monitoring

```python
# Get current health status
health = health_check_service.get_current_health()

# Get health statistics
stats = health_check_service.get_health_statistics()

# Generate report
report = health_check_service.get_status_report()
```

### 4. Validate Blocking Consistency

```python
from blocking_rules_validator import sync_validator

# Validate single IP
result = sync_validator.validate_sync("192.0.2.1")

# Validate all blocked IPs
all_results = sync_validator.validate_all_blocks()

if all_results['inconsistent'] > 0:
    # Alert admin
    logger.warning(f"Found {all_results['inconsistent']} inconsistent blocks")
```

---

## Monitoring & Troubleshooting

### Check Windows Firewall Rules

```powershell
# List all ThreatGuard rules
netsh advfirewall firewall show rule name="TG_BLOCK*"

# Check specific IP
netsh advfirewall firewall show rule name="TG_BLOCK_192_0_2_1*"

# Delete specific rule
netsh advfirewall firewall delete rule name="TG_BLOCK_192_0_2_1_IN"
```

### Check Linux iptables

```bash
# List all THREATGUARD rules
sudo iptables -L THREATGUARD -n

# Check specific IP
sudo iptables -C THREATGUARD -s 192.0.2.1 -j DROP

# Delete specific rule
sudo iptables -D THREATGUARD -s 192.0.2.1 -j DROP
```

### API Health Check

```bash
# Windows side
curl http://localhost:5000/api/blocking/health

# Linux agent
curl -H "Authorization: Bearer <TOKEN>" http://192.168.1.100:5001/api/health
```

### View Logs

```bash
# Windows (Python logs)
tail -f backend/logs/backend_debug.log

# Linux (Agent logs)
ssh kali@192.168.1.100
tail -f /opt/threatguard/logs/blocking_agent.log
```

---

## Testing

### 1. Test Windows Blocking

```python
# backend/test_windows_blocking.py
from windows_blocking_coordinator import coordinator

# Test block
result = coordinator.block_threat_ip(
    ip_address="192.0.2.1",
    threat_info={
        "category": "Test",
        "risk_score": 100,
        "reason": "Testing Windows blocking"
    }
)
print(f"Block result: {result}")

# Verify Windows rule exists
from blocking_rules_validator import WindowsRuleValidator
exists, msg = WindowsRuleValidator.verify_rule_exists("192.0.2.1")
print(f"Windows rule exists: {exists} - {msg}")
```

### 2. Test Linux Blocking

```bash
# SSH to Kali VM
ssh kali@192.168.1.100

# Test block via API
curl -X POST http://localhost:5001/api/blocking/block \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.0.2.1",
    "threat_category": "Test",
    "risk_score": 100,
    "reason": "Testing Linux blocking"
  }'

# Verify iptables rule exists
sudo iptables -C THREATGUARD -s 192.0.2.1 -j DROP && echo "Rule exists" || echo "Rule not found"
```

### 3. Test Sync Consistency

```python
from blocking_rules_validator import sync_validator

# Validate sync
result = sync_validator.validate_sync("192.0.2.1")
print(f"Sync consistent: {result['consistent']}")
print(f"Issues: {result['issues']}")
```

---

## Performance Considerations

- **Sync Timeout**: Default 30 seconds (configurable)
- **Retry Logic**: Up to 3 attempts with 30-second intervals
- **Database**: Blocking sync records indexed on IP for fast lookups
- **Cache**: In-memory blocked IP list for quick checks
- **Health Checks**: Every 60 seconds (configurable)

---

## Security Best Practices

1. **API Token**: Use strong, randomly generated tokens
2. **HTTPS**: Deploy with HTTPS in production
3. **IP Whitelist**: Restrict API access by source IP if possible
4. **Audit Logging**: All blocking operations logged with user/timestamp
5. **Database**: Use encrypted connection strings for remote databases
6. **SSH Keys**: Use SSH key-based auth for Kali VM (not password)

---

## Disaster Recovery

### Backup/Restore Blocked IPs

```bash
# Backup blocked IPs (Windows)
netsh advfirewall firewall show rule name="TG_BLOCK*" > /backup/firewall_rules.txt

# Backup blocked IPs (Linux)
sudo iptables-save > /backup/iptables_rules.txt
```

### Clear All Blocks

```python
# Emergency: Unblock all IPs
blocked_ips = coordinator.get_blocked_ips_list()
for ip_info in blocked_ips:
    coordinator.unblock_threat_ip(ip_info['ip'])
```

---

## Support & Troubleshooting

### Common Issues

1. **Linux API not reachable**
   - Check network connectivity: `ping 192.168.1.100`
   - Verify agent running: `systemctl status threatguard-agent`
   - Check firewall: `sudo ufw status`

2. **Duplicate rules**
   - Run validation: `sync_validator.validate_all_blocks()`
   - Auto-cleanup runs regularly

3. **Partial blocking (one system fails)**
   - Check health status: `health_check_service.get_current_health()`
   - Review sync logs: Check `SyncLog` table in database

---

**Deployment Version**: 1.0  
**Last Updated**: 2026-02-15
