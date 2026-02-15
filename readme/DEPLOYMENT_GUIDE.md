# ThreatGuard IP Auto-Blocking System - Complete Deployment Guide

## 🎯 Overview

This system provides **production-level automated and manual IP blocking** across your Windows host and Linux virtual machines. When a high-severity threat is detected or manually blocked from the admin dashboard, the IP is **instantly blocked on both systems** via real-time synchronization.

### Key Features

✅ **Automatic Blocking** - High-risk threats (score ≥ 75) auto-blocked in real-time  
✅ **Manual Blocking** - Admin dashboard control for instant IP blocking  
✅ **Two-Way Sync** - Windows ↔ Linux VM bidirectional synchronization  
✅ **WebSocket Real-Time** - Instant updates across all systems  
✅ **Centralized Database** - Single source of truth for all blocks  
✅ **Audit Logging** - Complete action history with timestamps  
✅ **Rollback Support** - Automatic rollback on failures  
✅ **Production-Ready** - Scalable, secure, and reliable

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    WINDOWS HOST (Admin System)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Flask Backend│  │   WebSocket  │  │  Auto-Block  │          │
│  │   API:5000   │  │  Server:8765 │  │   Monitor    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                  │                  │                   │
│         └──────────┬───────┴──────────────────┘                  │
│                    │                                              │
│  ┌─────────────────▼────────────────────────┐                   │
│  │  Blocking Sync Manager (Centralized)     │                   │
│  │  - Coordinates blocking operations       │                   │
│  │  - Ensures consistency                   │                   │
│  │  - Handles rollback                      │                   │
│  └─────────────────┬────────────────────────┘                   │
│                    │                                              │
│  ┌─────────────────▼────────────────────────┐                   │
│  │  Windows Defender Firewall (netsh)       │                   │
│  │  - Inbound/Outbound rules                │                   │
│  │  - ThreatGuard_Block_IN_xxx              │                   │
│  │  - ThreatGuard_Block_OUT_xxx             │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                   │
└──────────────────────┬────────────────────────────────────────-─┘
                       │ WebSocket (Port 8765)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                LINUX VM (Kali/Ubuntu - User System)              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────┐                   │
│  │   ThreatGuard Blocking Agent             │                   │
│  │   - Receives block/unblock commands      │                   │
│  │   - Manages iptables/ufw                 │                   │
│  │   - Sends confirmations                  │                   │
│  └─────────────────┬────────────────────────┘                   │
│                    │                                              │
│  ┌─────────────────▼────────────────────────┐                   │
│  │  iptables / UFW Firewall                 │                   │
│  │  - THREATGUARD_BLOCK chain               │                   │
│  │  - DROP rules for blocked IPs            │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites

### Windows Host Requirements

- **OS**: Windows 10/11 or Windows Server 2019+
- **Privileges**: Administrator access (required for firewall management)
- **Python**: Python 3.8+
- **Firewall**: Windows Defender Firewall enabled
- **Network**: Open ports 5000 (API) and 8765 (WebSocket)

### Linux VM Requirements

- **OS**: Kali Linux, Ubuntu 20.04+, Debian 10+, or compatible
- **Privileges**: Root/sudo access
- **Python**: Python 3.8+
- **Firewall**: iptables or ufw
- **Network**: Access to Windows host on ports 5000 and 8765

---

## 🚀 Installation

### Part 1: Windows Host Setup

#### Step 1: Deploy Windows Services

1. **Open PowerShell as Administrator**
   ```powershell
   cd C:\Users\nagul\Downloads\Final_Project\backend
   ```

2. **Run the deployment script**
   ```powershell
   .\DEPLOY_WINDOWS.ps1
   ```

   This will:
   - Install Python dependencies (websockets, asyncio)
   - Create required directories
   - Test Windows Firewall access
   - Create .env configuration
   - Generate startup scripts

#### Step 2: Create Admin User

```powershell
cd C:\Users\nagul\Downloads\Final_Project\backend
python create_admin.py
```

Enter admin credentials when prompted.

#### Step 3: Generate JWT Token

```powershell
python generate_admin_token.py
```

**IMPORTANT**: Copy the generated token - you'll need it for the VM agent!

#### Step 4: Start All Services

```powershell
.\start_all_services.ps1
```

This starts **three separate services**:
1. **Flask Backend API** (Port 5000)
2. **WebSocket Server** (Port 8765)
3. **Auto-Block Monitor** (Monitors threats every 2 minutes)

Verify services are running:
- Flask: http://localhost:5000/api/health
- WebSocket: Should show "WebSocket server running on ws://0.0.0.0:8765"

---

### Part 2: Linux VM Setup

#### Step 1: Copy VM Agent Files

Transfer the `vm_agent` folder to your Linux VM:

**Option A: Using SCP (from Windows)**
```powershell
scp -r vm_agent kali@[VM-IP]:/home/kali/
```

**Option B: Using Shared Folder**
- Copy the folder via VMware/VirtualBox shared folder
- Or use Git to clone the repository

#### Step 2: Run Deployment Script

On your Linux VM:

```bash
cd /home/kali/vm_agent  # Or wherever you copied the folder
sudo bash deploy_linux_vm.sh
```

This will:
- Install dependencies (python3, pip, iptables/ufw)
- Create agent directory at `/opt/threatguard_agent`
- Configure firewall chains
- Set up sudo permissions
- Create systemd service

#### Step 3: Configure Agent

Edit the configuration file:

```bash
sudo nano /opt/threatguard_agent/agent_config.json
```

Update the following (replace with your actual values):

```json
{
  "agent_id": "kali-vm-1",
  "websocket_url": "ws://192.168.1.100:8765",
  "api_url": "http://192.168.1.100:5000",
  "heartbeat_interval": 30,
  "reconnect_delay": 5,
  "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Replace**:
- `192.168.1.100` with your Windows host IP address
- `jwt_token` with the token generated in Part 1, Step 3

#### Step 4: Start VM Agent

**Option A: As a Systemd Service (Recommended)**

```bash
sudo systemctl enable threatguard-agent
sudo systemctl start threatguard-agent
sudo systemctl status threatguard-agent
```

**Option B: Manual Start (For Testing)**

```bash
cd /opt/threatguard_agent
sudo bash start_agent.sh
```

#### Step 5: Verify Agent Connection

Check the logs:

```bash
tail -f /opt/threatguard_agent/logs/blocking_agent.log
```

You should see:
```
[VM-AGENT] INFO - Connecting to WebSocket server: ws://192.168.1.100:8765
[VM-AGENT] INFO - ✅ Connected to WebSocket server as VM agent
```

---

## 🔧 Configuration

### Windows .env Configuration

Edit `backend/.env`:

```env
# Auto-Blocking Settings
AUTO_BLOCK_ENABLED=true
AUTO_BLOCK_THRESHOLD=75          # Block IPs with score >= 75
AUTO_BLOCK_CHECK_INTERVAL=120    # Check every 2 minutes
AUTO_BLOCK_MAX_PER_CYCLE=5       # Max 5 IPs per check
AUTO_BLOCK_DELAY=10               # 10 seconds delay between blocks

# WebSocket Settings
WS_HOST=0.0.0.0
WS_PORT=8765

# Optional: Kali VM SSH-based blocking (legacy)
KALI_VM_ENABLED=false
```

### Adjusting Auto-Block Sensitivity

| Threshold | Risk Level | Description |
|-----------|------------|-------------|
| 90+ | Critical | Only block extremely dangerous IPs |
| 75-89 | High | **Default** - High-risk threats |
| 60-74 | Medium-High | More aggressive blocking |
| 50-59 | Medium | Very aggressive |

---

## 🎮 Usage

### Automatic Blocking

High-severity threats are **automatically blocked** without any manual intervention:

1. **Threat Detection**: System fetches threats from OTX/database
2. **Score Evaluation**: Threats with score ≥ 75 are identified
3. **IP Extraction**: Valid IPs are extracted from threat indicators
4. **Synchronized Block**:
   - Windows firewall rule created (inbound + outbound)
   - Database record created
   - WebSocket broadcasts block command to VM
   - VM agent receives command and creates iptables/ufw rule
   - Confirmation sent back to host
5. **Logging**: All actions logged with timestamps

**Monitor auto-blocking**:
```powershell
# Windows
tail -f backend\logs\auto_block_monitor.log

# Linux VM
tail -f /opt/threatguard_agent/logs/blocking_agent.log
```

### Manual Blocking from Admin Dashboard

1. **Login** to admin dashboard: http://localhost:3000
2. **Navigate** to Threat Management
3. **Select** a threat or enter an IP manually
4. **Click** "Block IP"
5. **System automatically**:
   - Blocks on Windows firewall
   - Sends WebSocket command to VM
   - VM blocks the IP
   - Updates database
   - Logs the action

### Unblocking IPs

1. **Admin Dashboard** → Blocked IPs
2. **Select** the IP to unblock
3. **Click** "Unblock"
4. **System automatically**:
   - Removes Windows firewall rule
   - Sends unblock command to VM
   - VM removes iptables rule
   - Updates database

---

## 🔍 Verification & Testing

### Test 1: Verify Windows Firewall Rules

```powershell
# List all ThreatGuard rules
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"

# Check specific IP
netsh advfirewall firewall show rule name=all | Select-String "192.0.2.1"
```

### Test 2: Verify VM Firewall Rules

```bash
# iptables
sudo iptables -L THREATGUARD_BLOCK -n -v

# UFW
sudo ufw status numbered
```

### Test 3: End-to-End Block Test

On **Windows**:
```powershell
# Trigger a manual block via API
$token = "YOUR_JWT_TOKEN"
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$body = @{
    ip_address = "198.51.100.50"
    threat_type = "Test"
    risk_score = 85
    reason = "Manual test"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5000/api/admin/block-threat-sync" `
    -Method POST -Headers $headers -Body $body
```

**Expected Results**:
1. ✅ API returns success (201 Created)
2. ✅ Windows firewall rule created
3. ✅ WebSocket broadcasts to VM
4. ✅ VM creates iptables rule
5. ✅ Database updated
6. ✅ Logs show synchronization

Verify:
```bash
# On VM
sudo iptables -L THREATGUARD_BLOCK -n -v | grep 198.51.100.50
```

### Test 4: Check WebSocket Connection

On **Windows** (check WebSocket server logs):
```powershell
# Should show connected VM agents
Get-Content backend\logs\websocket_server.log -Tail 20
```

Look for:
```
[WS] INFO - VM Agent connected (ID: kali-vm-1). Total agents: 1
```

---

## 📊 Monitoring & Logs

### Windows Host Logs

| Log File | Purpose |
|----------|---------|
| `backend/logs/auto_block_monitor.log` | Auto-blocking activity |
| `backend/logs/blocking_sync.log` | Synchronization operations |
| `backend/logs/websocket_server.log` | WebSocket connections |
| `backend/backend_log.txt` | Flask API logs |

### Linux VM Logs

| Log File | Purpose |
|----------|---------|
| `/opt/threatguard_agent/logs/blocking_agent.log` | Agent activity |
| `/opt/threatguard_agent/logs/service.log` | Systemd service output |
| `/opt/threatguard_agent/blocked_ips.json` | Blocked IPs list |

### Real-Time Monitoring

**Windows PowerShell**:
```powershell
# Monitor auto-blocking
Get-Content backend\logs\auto_block_monitor.log -Wait

# Monitor sync operations
Get-Content backend\logs\blocking_sync.log -Wait
```

**Linux Terminal**:
```bash
# Monitor agent
tail -f /opt/threatguard_agent/logs/blocking_agent.log

# Watch iptables in real-time
watch -n 2 'sudo iptables -L THREATGUARD_BLOCK -n -v'
```

---

## 🛠️ Troubleshooting

### Issue: Auto-blocking not working

**Symptoms**: High-severity threats not being blocked

**Solutions**:
1. Check if auto-block monitor is running:
   ```powershell
   Get-Process python | Where-Object {$_.MainWindowTitle -like "*auto_block_monitor*"}
   ```

2. Verify JWT token:
   ```powershell
   cat .auto_blocker_token
   ```

3. Check logs for errors:
   ```powershell
   Get-Content backend\logs\auto_block_monitor.log -Tail 50
   ```

4. Ensure AUTO_BLOCK_ENABLED=true in .env

---

### Issue: VM agent not connecting

**Symptoms**: "Connection failed" in VM logs

**Solutions**:
1. **Verify Windows host IP** in agent_config.json
   ```bash
   cat /opt/threatguard_agent/agent_config.json
   ```

2. **Test network connectivity**:
   ```bash
   ping [WINDOWS_HOST_IP]
   telnet [WINDOWS_HOST_IP] 8765
   ```

3. **Check Windows firewall allows port 8765**:
   ```powershell
   netsh advfirewall firewall add rule name="ThreatGuard_WS" dir=in action=allow protocol=TCP localport=8765
   ```

4. **Verify JWT token is valid**:
   - Re-generate token on Windows: `python generate_admin_token.py`
   - Update token in VM config
   - Restart agent: `sudo systemctl restart threatguard-agent`

---

### Issue: Blocking fails on Windows

**Symptoms**: "ADMIN PRIVILEGES REQUIRED" error

**Solutions**:
1. **Restart backend as Administrator**:
   - Right-click PowerShell → Run as Administrator
   - Run: `python app.py`

2. **Verify firewall is enabled**:
   ```powershell
   netsh advfirewall show currentprofile
   ```

3. **Test manual rule creation**:
   ```powershell
   netsh advfirewall firewall add rule name="TEST" dir=in action=block remoteip=1.2.3.4
   netsh advfirewall firewall delete rule name="TEST"
   ```

---

### Issue: Blocking fails on Linux VM

**Symptoms**: "Permission denied" or iptables errors

**Solutions**:
1. **Check sudo permissions**:
   ```bash
   sudo -l
   ```
   Should show ThreatGuard iptables commands as NOPASSWD

2. **Verify sudoers file**:
   ```bash
   sudo cat /etc/sudoers.d/threatguard
   ```

3. **Test manual iptables**:
   ```bash
   sudo iptables -A THREATGUARD_BLOCK -s 1.2.3.4 -j DROP
   sudo iptables -D THREATGUARD_BLOCK -s 1.2.3.4 -j DROP
   ```

4. **Check firewall is active**:
   ```bash
   sudo iptables -L -n -v
   # or
   sudo ufw status
   ```

---

### Issue: Database conflicts

**Symptoms**: "IP already blocked" when it shouldn't be

**Solutions**:
1. **Check database**:
   ```powershell
   cd backend
   python
   >>> from app import db, BlockedThreat
   >>> BlockedThreat.query.filter_by(is_active=True).all()
   ```

2. **Clear ghost entries**:
   ```powershell
   python clear_admin_blocked_ips.py
   ```

3. **Sync firewall with database**:
   - Restart all services
   - VM agent will restore rules from blocked_ips.json on startup

---

## 🔒 Security Considerations

### JWT Token Security

- **Never commit** tokens to version control
- **Rotate tokens** every 30 days
- **Use strong SECRET_KEY** in .env
- **Restrict token file permissions**:
  ```bash
  chmod 600 .auto_blocker_token
  ```

### Network Security

- **Firewall rules**: Restrict ports 5000/8765 to trusted networks only
- **TLS/SSL**: In production, use HTTPS and WSS (secure WebSocket)
- **VPN**: Consider running over VPN for VM communication

### Privilege Escalation Prevention

- **Minimal sudo**: Only grant iptables commands, not full sudo
- **Audit logs**: Regularly review blocking logs
- **Whitelist**: Maintain whitelist of critical IPs to never block

---

## 📈 Performance & Scaling

### Current Limits

- **Auto-block**: 5 IPs per 2-minute cycle (configurable)
- **WebSocket**: Supports multiple VM agents
- **Database**: SQLite (upgrade to PostgreSQL for production)

### Scaling to Multiple VMs

1. **Each VM** runs its own agent with unique agent_id
2. **WebSocket server** broadcasts to all connected agents
3. **All VMs** receive and enforce the same blocks
4. **No conflicts**: Each agent maintains its own blocked_ips.json

To add more VMs:
1. Deploy agent to new VM
2. Configure agent_config.json with unique agent_id
3. Start agent - it will automatically sync with existing blocks

---

## 📝 API Reference

### Admin Blocking Endpoints

#### Block IP with Synchronization
```http
POST /api/admin/block-threat-sync
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "ip_address": "192.0.2.1",
  "threat_type": "Malware C2",
  "risk_category": "High",
  "risk_score": 85,
  "summary": "Known malware command & control server",
  "reason": "Manual block - confirmed malicious"
}
```

**Response** (201 Created):
```json
{
  "message": "IP 192.0.2.1 blocked successfully on Windows and VM",
  "blocked_threat": {
    "id": 123,
    "ip_address": "192.0.2.1",
    "blocked_at": "2026-02-14T10:30:00Z"
  }
}
```

#### Unblock IP with Synchronization
```http
POST /api/admin/unblock-threat-sync/<threat_id>
Authorization: Bearer <JWT_TOKEN>
```

**Response** (200 OK):
```json
{
  "message": "IP 192.0.2.1 unblocked successfully"
}
```

#### Get Synchronization Status
```http
GET /api/admin/sync-status
Authorization: Bearer <JWT_TOKEN>
```

**Response**:
```json
{
  "sync_manager_available": true,
  "status": {
    "pending_operations": 0,
    "failed_operations": 0,
    "pending_ips": [],
    "failed_ips": []
  },
  "timestamp": "2026-02-14T10:30:00Z"
}
```

#### Get VM Agents Status
```http
GET /api/admin/vm-agents
Authorization: Bearer <JWT_TOKEN>
```

**Response**:
```json
{
  "vm_agents_count": 2,
  "agents": [
    {
      "connected": true,
      "timestamp": "2026-02-14T10:30:00Z"
    },
    {
      "connected": true,
      "timestamp": "2026-02-14T10:30:00Z"
    }
  ],
  "websocket_available": true
}
```

---

## 🔄 Update & Maintenance

### Update Backend Code

```powershell
cd C:\Users\nagul\Downloads\Final_Project\backend
git pull  # If using Git

# Restart services
# Kill existing processes, then:
.\start_all_services.ps1
```

### Update VM Agent

```bash
cd /home/kali/vm_agent
git pull  # If using Git

# Copy new agent code
sudo cp blocking_agent.py /opt/threatguard_agent/

# Restart service
sudo systemctl restart threatguard-agent
```

### Database Backup

```powershell
# Backup SQLite database
cd backend\instance
copy users.db users.db.backup

# Backup blocked IPs
copy ..\blocked_ips.json blocked_ips.json.backup
```

---

## ❓ FAQ

**Q: Can I block entire IP ranges?**  
A: Not directly supported yet. Modify IP validation to accept CIDR notation.

**Q: What happens if the VM is offline?**  
A: Windows blocks will still work. When VM comes back online, it syncs blocked IPs from its local JSON file.

**Q: Can I use this with Docker containers?**  
A: Yes, but iptables rules may need adjustment for Docker networks.

**Q: Does this work with IPv6?**  
A: Partially. IPv4 is fully supported; IPv6 needs additional validation logic.

**Q: Can regular users trigger blocking?**  
A: No, only admins can trigger blocking (manual or automatic).

---

## 📞 Support & Contact

**Issues**: Check logs first, then review troubleshooting section  
**Documentation**: This guide + inline code comments  
**Logs**: Always check both Windows and Linux logs for errors

---

## 📄 License & Credits

ThreatGuard IP Auto-Blocking System  
Developed for Cyber Threat Intelligence Platform  
Author: Senior Cybersecurity Engineering Team  
Date: February 2026

---

**System Status**: ✅ Production Ready  
**Last Updated**: February 14, 2026
