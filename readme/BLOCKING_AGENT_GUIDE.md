# 🛡️ ThreatGuard Blocking Agent - Complete Guide

## 📋 Overview

The **ThreatGuard Blocking Agent** is a lightweight, distributed security component that extends IP blocking capabilities across multiple machines in your network. While the main backend runs on Windows, the agent allows you to deploy synchronized blocking on Linux systems, creating a **distributed defense perimeter**.

### Why Use Blocking Agents?

```
┌─────────────────────────────────────────────────────────────┐
│              WITHOUT AGENTS (Single Point)                   │
└─────────────────────────────────────────────────────────────┘

    Attacker ──────> Windows Server (Backend)
                           │
                           │ Blocks only here
                           ▼
                     [Windows Firewall]


┌─────────────────────────────────────────────────────────────┐
│              WITH AGENTS (Distributed Defense)               │
└─────────────────────────────────────────────────────────────┘

                    Central Backend (Windows)
                           │
                           │ Detects threat & coordinates
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
    Agent 1            Agent 2            Agent 3
    (Kali VM)       (Ubuntu Server)   (User Laptop)
        │                  │                  │
        ▼                  ▼                  ▼
    [iptables]        [iptables]        [iptables]

    ALL systems block the threat simultaneously!
```

---

## 🎯 Key Benefits

### 1. **Distributed Protection**
- Block threats across **all connected endpoints**, not just the central server
- Create a **network-wide security perimeter**
- Protect individual user machines and servers

### 2. **Real-Time Synchronization**
- Blocks propagate to all agents within **seconds**
- Centralized threat intelligence distribution
- Consistent security posture across infrastructure

### 3. **Cross-Platform Support**
- **Windows Backend**: Main server with threat intelligence
- **Linux Agents**: Deploy on Kali, Ubuntu, Debian, CentOS, etc.
- **Lightweight**: Minimal resource footprint (~10MB memory)

### 4. **Autonomous Operation**
- Agents run independently once installed
- Auto-reconnect on network interruption
- Local caching for offline resilience

---

## 🏗️ Architecture

### System Components

```
┌──────────────────────────────────────────────────────────────┐
│                    CENTRAL BACKEND                            │
│                    (Windows Server)                          │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Threat Intelligence Engine                         │     │
│  │  - AlienVault OTX API                              │     │
│  │  - Google Gemini AI Analysis                       │     │
│  │  - Risk Scoring & Categorization                   │     │
│  └────────────────────────────────────────────────────┘     │
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Blocking Sync Service                             │     │
│  │  - Coordinates blocking across systems             │     │
│  │  - REST API: /api/blocking/sync                    │     │
│  │  - WebSocket for real-time updates                 │     │
│  └────────────────────────────────────────────────────┘     │
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Windows Firewall Manager                          │     │
│  │  - netsh advfirewall commands                      │     │
│  │  - IN + OUT rules per IP                           │     │
│  └────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
                            │
                            │ HTTP/WebSocket
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  AGENT 1      │   │  AGENT 2      │   │  AGENT 3      │
│  (Kali VM)    │   │  (Ubuntu)     │   │  (Red Hat)    │
│               │   │               │   │               │
│  Components:  │   │  Components:  │   │  Components:  │
│  • Agent Daemon│  │  • Agent Daemon│  │  • Agent Daemon│
│  • iptables   │   │  • iptables   │   │  • iptables   │
│  • Log Monitor│   │  • Log Monitor│   │  • Log Monitor│
└───────────────┘   └───────────────┘   └───────────────┘
```

---

## 📥 Agent Installation

### Prerequisites

**On Each Agent Machine:**
- Linux OS (Kali, Ubuntu, Debian, CentOS, Red Hat)
- Bash shell 4.0+
- `iptables` package installed
- `curl` or `wget` for API calls
- Root/sudo privileges
- Network connectivity to backend server

### Step 1: Download Agent Script

```bash
# SSH into your Linux machine
ssh user@agent-machine

# Download the agent script from backend
cd /opt
sudo mkdir -p threatguard-agent
cd threatguard-agent

# Download from backend (replace with your backend IP)
sudo curl -O http://192.168.1.100:5000/static/kali_blocker_agent.sh

# Or manually copy the script from backend/kali_blocker_agent.sh
```

### Step 2: Configure Agent

```bash
# Edit the configuration
sudo nano /opt/threatguard-agent/kali_blocker_agent.sh

# Update these lines:
BACKEND_URL="http://192.168.1.100:5000"  # Your Windows backend IP
API_TOKEN="your-secure-api-token-here"    # From backend .env
CHECK_INTERVAL=60                         # Check every 60 seconds
```

**Configuration Parameters:**

| Parameter | Description | Default | Recommendation |
|-----------|-------------|---------|----------------|
| `BACKEND_URL` | IP/hostname of central backend | `http://192.168.1.100:5000` | Use static IP or hostname |
| `API_TOKEN` | Authentication token | (required) | Generate secure token |
| `CHECK_INTERVAL` | Polling frequency (seconds) | `60` | 30-120 seconds |
| `LOG_FILE` | Path to agent log file | `/var/log/threatguard.log` | Writable location |
| `BLOCKED_IPS_FILE` | Local IP cache | `/opt/threatguard-agent/.blocked_ips` | Persistent storage |

### Step 3: Make Script Executable

```bash
sudo chmod +x /opt/threatguard-agent/kali_blocker_agent.sh
```

### Step 4: Test Agent (Manual Mode)

```bash
# Test blocking a single IP
sudo /opt/threatguard-agent/kali_blocker_agent.sh block 203.0.113.100 "Test"

# Expected output:
# [2026-02-21 10:30:15] [SUCCESS] Blocked IP: 203.0.113.100 - Reason: Test
# ✓ Blocked 203.0.113.100

# Verify iptables rule created
sudo iptables -L INPUT -n | grep 203.0.113.100

# Test unblocking
sudo /opt/threatguard-agent/kali_blocker_agent.sh unblock 203.0.113.100

# Check status
sudo /opt/threatguard-agent/kali_blocker_agent.sh status
```

### Step 5: Install as System Service

#### Option A: Systemd Service (Ubuntu, Debian, Modern Linux)

```bash
# Create systemd service file
sudo nano /etc/systemd/system/threatguard-agent.service
```

**Service File Content:**
```ini
[Unit]
Description=ThreatGuard Blocking Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/threatguard-agent/kali_blocker_agent.sh daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Enable and Start Service:**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable threatguard-agent

# Start service now
sudo systemctl start threatguard-agent

# Check status
sudo systemctl status threatguard-agent

# View logs
sudo journalctl -u threatguard-agent -f
```

#### Option B: Cron Job (Alternative)

```bash
# Edit root crontab
sudo crontab -e

# Add this line to run agent every minute
* * * * * /opt/threatguard-agent/kali_blocker_agent.sh daemon >> /var/log/threatguard.log 2>&1
```

### Step 6: Verify Installation

```bash
# Check if service is running
sudo systemctl status threatguard-agent

# Check recent logs
sudo tail -f /var/log/threatguard.log

# Expected log output:
# [2026-02-21 10:35:00] [INFO] ThreatGuard Blocker Agent Started
# [2026-02-21 10:35:00] [INFO] Backend URL: http://192.168.1.100:5000
# [2026-02-21 10:35:05] [INFO] Checking for new threats to block...
# [2026-02-21 10:35:05] [SUCCESS] Connected to backend
# [2026-02-21 10:35:05] [INFO] 0 new IPs to block

# Test connectivity to backend
curl http://192.168.1.100:5000/api/health
```

---

## 🔄 How Agent Synchronization Works

### Complete Sync Workflow

```
┌──────────────────────────────────────────────────────────────┐
│               THREAT DETECTION & SYNC WORKFLOW                │
└──────────────────────────────────────────────────────────────┘

1. Threat Detected on Backend (Windows)
   │
   ▼
   High-risk IP identified: 203.0.113.45
   Risk Score: 92.5
   Category: Malware C2 Server
   │
   ▼
2. Backend Blocks Locally
   │
   ├─> Create Windows Firewall rule (IN)
   ├─> Create Windows Firewall rule (OUT)
   └─> Save to database: blocked_threat table
   │
   ▼
3. Backend Notifies Agents
   │
   ├─> POST /api/blocking/sync
   │   Body: {
   │     "action": "block",
   │     "ip": "203.0.113.45",
   │     "reason": "Malware C2 Server",
   │     "risk_score": 92.5,
   │     "timestamp": "2026-02-21T10:35:10Z"
   │   }
   │
   └─> WebSocket broadcast to connected agents
       Event: "block_command"
   │
   ▼
4. Agents Poll Backend (Every 60 seconds)
   │
   Agent 1 ────> GET /api/blocking/list?since=last_sync
   Agent 2 ────> GET /api/blocking/list?since=last_sync
   Agent 3 ────> GET /api/blocking/list?since=last_sync
   │
   Each agent receives:
   {
     "blocked_ips": [
       {
         "ip": "203.0.113.45",
         "reason": "Malware C2 Server",
         "risk_score": 92.5,
         "blocked_at": "2026-02-21T10:35:10Z"
       }
     ]
   }
   │
   ▼
5. Agents Execute Blocking
   │
   Agent 1: sudo iptables -I INPUT -s 203.0.113.45 -j DROP
   Agent 2: sudo iptables -I INPUT -s 203.0.113.45 -j DROP
   Agent 3: sudo iptables -I INPUT -s 203.0.113.45 -j DROP
   │
   ▼
6. Agents Report Back
   │
   POST /api/blocking/agent-status
   Body: {
     "agent_id": "agent-1-hostname",
     "status": "success",
     "ip": "203.0.113.45",
     "timestamp": "2026-02-21T10:35:15Z"
   }
   │
   ▼
7. Backend Updates Dashboard
   │
   WebSocket broadcast to admin dashboard:
   {
     "event": "agent_sync_complete",
     "data": {
       "ip": "203.0.113.45",
       "agents_synced": 3,
       "total_agents": 3,
       "sync_time_seconds": 5
     }
   }
   │
   ▼
RESULT: IP blocked on ALL systems!
   - Windows Server: ✓ Blocked via netsh
   - Agent 1: ✓ Blocked via iptables
   - Agent 2: ✓ Blocked via iptables
   - Agent 3: ✓ Blocked via iptables
```

---

## 🔐 Security Considerations

### Authentication & Authorization

#### 1. **API Token System**

**Backend Configuration (`.env`):**
```bash
# Generate a secure token (32+ characters)
AGENT_API_TOKEN=threatguard_secure_token_abc123xyz789

# Require token for agent endpoints
AGENT_REQUIRE_TOKEN=true
```

**Agent Configuration:**
```bash
# In kali_blocker_agent.sh
API_TOKEN="threatguard_secure_token_abc123xyz789"

# Agent includes token in all requests
curl -H "Authorization: Bearer $API_TOKEN" \
     http://backend:5000/api/blocking/list
```

#### 2. **Token Validation Flow**

```python
# Backend: app.py
def require_agent_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if AGENT_REQUIRE_TOKEN:
            if not AGENT_API_TOKEN or token != AGENT_API_TOKEN:
                return jsonify({"error": "Invalid agent token"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/blocking/list")
@require_agent_token
def get_blocked_ips_for_agents():
    # Only accessible with valid token
    pass
```

### Network Security

#### 1. **Use HTTPS in Production**

```bash
# Backend (use reverse proxy like Nginx)
BACKEND_URL="https://threatguard.company.com"

# Agent verifies SSL certificate
curl --cacert /etc/ssl/certs/ca-bundle.crt \
     -H "Authorization: Bearer $API_TOKEN" \
     https://threatguard.company.com/api/blocking/list
```

#### 2. **Firewall Rules for Agent Communication**

**On Backend (Windows):**
```powershell
# Allow only specific agent IPs to access API
New-NetFirewallRule -DisplayName "ThreatGuard Agent API" `
  -Direction Inbound -LocalPort 5000 -Protocol TCP `
  -Action Allow -RemoteAddress 192.168.1.50,192.168.1.51,192.168.1.52
```

**On Agents (Linux):**
```bash
# Allow only backend IP
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT
sudo iptables -A INPUT -p tcp -j DROP
```

#### 3. **Rate Limiting**

```python
# Backend: Limit agent API calls
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/blocking/list")
@limiter.limit("10 per minute")  # Max 10 requests/minute per IP
@require_agent_token
def get_blocked_ips_for_agents():
    pass
```

---

## 📊 Monitoring & Management

### Backend Dashboard - Agent Status

**View Connected Agents:**
```
Admin Dashboard → Agent Status

┌─────────────────────────────────────────────────────────┐
│               CONNECTED AGENTS STATUS                    │
├─────────────────────────────────────────────────────────┤
│ Agent ID         │ IP Address    │ Status  │ Last Seen │
├──────────────────┼───────────────┼─────────┼───────────┤
│ kali-vm-01       │ 192.168.1.50  │ Online  │ 10s ago   │
│ ubuntu-server-02 │ 192.168.1.51  │ Online  │ 12s ago   │
│ redhat-prod-03   │ 192.168.1.52  │ Offline │ 5m ago    │
├──────────────────┴───────────────┴─────────┴───────────┤
│ Total Agents: 3  │  Online: 2  │  Offline: 1          │
└─────────────────────────────────────────────────────────┘

Sync Statistics:
  - Total IPs Synced: 247
  - Average Sync Time: 3.2 seconds
  - Failed Syncs: 2 (0.8%)
```

### Backend API Endpoints

#### 1. **Get Agent Status**
```bash
GET http://backend:5000/api/admin/agent-status
Authorization: Bearer {admin_jwt_token}

Response:
{
  "agents": [
    {
      "agent_id": "kali-vm-01",
      "ip_address": "192.168.1.50",
      "status": "online",
      "last_heartbeat": "2026-02-21T10:40:00Z",
      "blocked_ips_count": 247,
      "version": "1.0.0"
    }
  ],
  "total_agents": 3,
  "online_agents": 2
}
```

#### 2. **Get Agent Enforcement History**
```bash
GET http://backend:5000/api/admin/agent-enforcements
Authorization: Bearer {admin_jwt_token}

Response:
{
  "enforcements": [
    {
      "ip": "203.0.113.45",
      "action": "block",
      "timestamp": "2026-02-21T10:35:10Z",
      "agents_synced": 2,
      "total_agents": 3,
      "failed_agents": ["redhat-prod-03"]
    }
  ]
}
```

### Agent-Side Monitoring

#### Check Agent Logs
```bash
# Real-time log monitoring
sudo tail -f /var/log/threatguard.log

# Check last 100 lines
sudo tail -n 100 /var/log/threatguard.log

# Search for errors
sudo grep "ERROR" /var/log/threatguard.log

# Count blocked IPs
sudo grep "Blocked IP" /var/log/threatguard.log | wc -l
```

#### Check Blocked IPs
```bash
# View all blocked IPs in iptables
sudo iptables -L INPUT -n | grep DROP

# Count DROP rules
sudo iptables -L INPUT -n | grep DROP | wc -l

# View agent's cached IP list
cat /opt/threatguard-agent/.blocked_ips
```

#### Agent Health Check Script
```bash
#!/bin/bash
# /opt/threatguard-agent/health_check.sh

echo "ThreatGuard Agent Health Check"
echo "==============================="

# Check if service running
if systemctl is-active --quiet threatguard-agent; then
    echo "✓ Service: Running"
else
    echo "✗ Service: Stopped"
fi

# Check backend connectivity
if curl -s -o /dev/null -w "%{http_code}" http://192.168.1.100:5000/api/health | grep -q "200"; then
    echo "✓ Backend: Connected"
else
    echo "✗ Backend: Unreachable"
fi

# Count blocked IPs
BLOCKED_COUNT=$(sudo iptables -L INPUT -n | grep DROP | wc -l)
echo "✓ Blocked IPs: $BLOCKED_COUNT"

# Check log file
if [ -f "/var/log/threatguard.log" ]; then
    ERRORS=$(grep -c "ERROR" /var/log/threatguard.log)
    echo "✓ Log Errors: $ERRORS"
fi

echo "==============================="
```

---

## 🔧 Troubleshooting

### Common Issues & Solutions

#### Issue 1: Agent Cannot Connect to Backend

**Symptoms:**
```
[2026-02-21 10:40:00] [ERROR] Failed to connect to backend
Connection refused
```

**Solutions:**
```bash
# 1. Verify backend is running
curl http://192.168.1.100:5000/api/health

# 2. Check network connectivity
ping 192.168.1.100

# 3. Check firewall on backend (Windows)
# PowerShell on backend:
Test-NetConnection -ComputerName localhost -Port 5000

# 4. Verify agent configuration
grep BACKEND_URL /opt/threatguard-agent/kali_blocker_agent.sh

# 5. Check backend firewall allows agent IP
# Windows Firewall → Inbound Rules → Port 5000
```

#### Issue 2: Authentication Failure

**Symptoms:**
```
[2026-02-21 10:41:00] [ERROR] Authentication failed: 403 Forbidden
```

**Solutions:**
```bash
# 1. Verify API token matches
# On backend (.env):
echo $AGENT_API_TOKEN

# On agent:
grep API_TOKEN /opt/threatguard-agent/kali_blocker_agent.sh

# 2. Test token manually
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     http://192.168.1.100:5000/api/blocking/list

# 3. Regenerate token if needed
# Backend: Update .env with new token
# Agent: Update configuration with same token
```

#### Issue 3: iptables Rules Not Created

**Symptoms:**
```
[2026-02-21 10:42:00] [ERROR] Failed to block IP: 203.0.113.45
iptables: Permission denied
```

**Solutions:**
```bash
# 1. Check if running with sudo
sudo systemctl status threatguard-agent

# 2. Verify iptables installed
which iptables
sudo iptables -L

# 3. Check if service runs as root
# In /etc/systemd/system/threatguard-agent.service:
# User=root

# 4. Test manual blocking
sudo /opt/threatguard-agent/kali_blocker_agent.sh block 203.0.113.45 "Test"

# 5. Check SELinux (if applicable)
getenforce  # Should be Permissive or Disabled for testing
sudo setenforce 0  # Temporary disable
```

#### Issue 4: Agent Goes Offline Frequently

**Symptoms:**
- Dashboard shows agent as "Offline"
- Intermittent connectivity

**Solutions:**
```bash
# 1. Increase polling interval
# In kali_blocker_agent.sh:
CHECK_INTERVAL=120  # 2 minutes instead of 60 seconds

# 2. Check system resources
top
free -h
df -h

# 3. Review systemd restart policy
# In service file:
Restart=always
RestartSec=10

# 4. Check network stability
ping -c 100 192.168.1.100 | grep "packet loss"

# 5. Enable debug logging
# Add to agent script:
set -x  # Enable debug mode
```

#### Issue 5: Blocked IPs Not Synchronized

**Symptoms:**
- Backend shows IP blocked
- Agent doesn't have the rule

**Solutions:**
```bash
# 1. Manually trigger sync
sudo systemctl restart threatguard-agent

# 2. Check backend sync endpoint
curl -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.100:5000/api/blocking/list

# 3. Compare blocked lists
# Backend:
curl http://backend:5000/api/admin/blocked-ips

# Agent:
sudo iptables -L INPUT -n | grep DROP

# 4. Clear agent cache and re-sync
sudo rm /opt/threatguard-agent/.blocked_ips
sudo systemctl restart threatguard-agent

# 5. Check sync logs
sudo journalctl -u threatguard-agent | grep "sync\|Blocked"
```

---

## 📈 Performance & Scalability

### Resource Requirements

**Per Agent:**
- **CPU**: <1% (idle), <5% (during sync)
- **Memory**: ~10MB
- **Disk**: <5MB (logs + cache)
- **Network**: <1KB/minute (polling overhead)

**Scaling Guidelines:**
- **Small Deployment**: 1-10 agents, 60s polling interval
- **Medium Deployment**: 10-50 agents, 90s polling interval
- **Large Deployment**: 50-200 agents, 120s polling interval, consider WebSocket push

### Optimization Tips

#### 1. **Batch Blocking**
```bash
# Instead of blocking IPs one-by-one, batch process
# In agent script, modify block_ip() to queue IPs:

BLOCK_QUEUE=()

queue_ip_block() {
    BLOCK_QUEUE+=("$1")
}

flush_block_queue() {
    for ip in "${BLOCK_QUEUE[@]}"; do
        sudo iptables -I INPUT -s "$ip" -j DROP
    done
    BLOCK_QUEUE=()
}
```

#### 2. **Delta Sync Instead of Full List**
```bash
# Agent only fetches IPs added since last sync
last_sync_time=$(cat /opt/threatguard-agent/.last_sync)
curl "http://backend:5000/api/blocking/list?since=$last_sync_time"
```

#### 3. **WebSocket Push (Advanced)**
```bash
# Instead of polling, agents connect via WebSocket
# Backend pushes blocks immediately
# Reduces latency from 60s → <1s

# Install: npm install -g wscat
wscat -c ws://192.168.1.100:8080/agent \
      -H "Authorization: Bearer $TOKEN"
```

---

## 🎓 Best Practices

### 1. **Deployment Strategy**

#### Phased Rollout
```
Phase 1: Deploy to 2-3 test agents
         Monitor for 1 week
         Verify logs and connectivity

Phase 2: Deploy to 25% of production agents
         Monitor for issues
         Adjust polling intervals

Phase 3: Deploy to all agents
         Full production monitoring
```

### 2. **Security Hardening**

```bash
# 1. Use SSH key authentication (no passwords)
ssh-keygen -t ed25519 -C "threatguard-agent"

# 2. Restrict agent SSH access
# In /etc/ssh/sshd_config:
AllowUsers threatguard-agent@192.168.1.100

# 3. Enable firewall on agents
sudo ufw enable
sudo ufw allow from 192.168.1.100 to any port 22

# 4. Regular log rotation
# Create /etc/logrotate.d/threatguard:
/var/log/threatguard.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

### 3. **Monitoring & Alerting**

```bash
# Set up monitoring for agent health
# Example: Prometheus + Grafana

# Agent exports metrics
curl http://agent:9100/metrics

# Alert on:
# - Agent offline > 5 minutes
# - Sync failures > 3 consecutive
# - High CPU/memory usage
# - iptables rule count exceeds threshold
```

### 4. **Documentation**

Maintain a registry of all agents:
```
agents_registry.csv:
agent_id,hostname,ip_address,location,owner,deployed_date,status
agent-1,kali-vm-01,192.168.1.50,Data Center A,Security Team,2026-01-15,active
agent-2,ubuntu-srv,192.168.1.51,Cloud AWS,DevOps,2026-01-20,active
agent-3,redhat-prod,192.168.1.52,Office HQ,IT Dept,2026-02-01,maintenance
```

---

## 🚀 Quick Start Summary

### For Users: Installing an Agent on Your Machine

```bash
# 1. Download agent script
wget http://backend:5000/static/kali_blocker_agent.sh

# 2. Configure
nano kali_blocker_agent.sh
# Set: BACKEND_URL and API_TOKEN

# 3. Install as service
sudo mv kali_blocker_agent.sh /opt/threatguard-agent/
sudo chmod +x /opt/threatguard-agent/kali_blocker_agent.sh

# 4. Create systemd service
sudo nano /etc/systemd/system/threatguard-agent.service
# (Copy service file from above)

# 5. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable threatguard-agent
sudo systemctl start threatguard-agent

# 6. Verify
sudo systemctl status threatguard-agent
sudo tail -f /var/log/threatguard.log

# Done! Your machine is now part of the distributed defense network.
```

---

## 📞 Support

### Documentation
- Main project: `PROJECT_METHODOLOGY.md`
- Workflow guide: `SYSTEM_WORKFLOW.md`
- This guide: `BLOCKING_AGENT_GUIDE.md`

### Logs to Check
- **Backend**: `backend/backend_log.txt`
- **Agent**: `/var/log/threatguard.log`
- **Systemd**: `journalctl -u threatguard-agent`

### Common Commands Reference

```bash
# Agent Management
sudo systemctl start threatguard-agent
sudo systemctl stop threatguard-agent
sudo systemctl restart threatguard-agent
sudo systemctl status threatguard-agent

# View Logs
sudo journalctl -u threatguard-agent -f
sudo tail -f /var/log/threatguard.log

# Manual Operations
sudo /opt/threatguard-agent/kali_blocker_agent.sh block <IP> <reason>
sudo /opt/threatguard-agent/kali_blocker_agent.sh unblock <IP>
sudo /opt/threatguard-agent/kali_blocker_agent.sh status

# Check Firewall
sudo iptables -L INPUT -n | grep DROP
sudo iptables -L INPUT -n | grep DROP | wc -l
```

---

**Document Version**: 1.0  
**Last Updated**: February 21, 2026  
**Status**: Production Ready  
**Compatibility**: Linux (Kali, Ubuntu, Debian, CentOS, Red Hat)
