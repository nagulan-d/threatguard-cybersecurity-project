# ThreatGuard Auto-Blocking System - Quick Start Guide

## 🚀 30-Second Overview

**Automatic + Manual IP Blocking** across **Windows Host** ↔ **Linux VM** with **real-time synchronization**

- ✅ Auto-blocks high-risk threats (score ≥ 75)
- ✅ Manual blocking from admin dashboard
- ✅ Instant sync via WebSocket
- ✅ Windows Firewall + Linux iptables/ufw
- ✅ Complete audit logging

---

## ⚡ 5-Minute Setup

### Windows Host (Admin Computer)

```powershell
# 1. Run as Administrator
cd C:\Users\nagul\Downloads\Final_Project\backend
.\DEPLOY_WINDOWS.ps1

# 2. Create admin user
python create_admin.py

# 3. Generate token
python generate_admin_token.py
# ⚠️ COPY THE TOKEN - You'll need it for Linux VM

# 4. Start all services
.\start_all_services.ps1
```

**Services Started**:
- Backend API: http://localhost:5000
- WebSocket: ws://localhost:8765
- Auto-block monitor (checks every 2 minutes)

---

### Linux VM (Kali/Ubuntu)

```bash
# 1. Copy vm_agent folder to Linux
cd vm_agent

# 2. Run deployment
sudo bash deploy_linux_vm.sh

# 3. Configure with Windows host IP
sudo nano /opt/threatguard_agent/agent_config.json

# Change:
#   websocket_url: ws://192.168.1.100:8765  (your Windows IP)
#   jwt_token: [paste token from Windows step 3]

# 4. Start agent
sudo systemctl start threatguard-agent
sudo systemctl status threatguard-agent
```

---

## ✅ Verify It's Working

### Test 1: Check Services

**Windows**:
```powershell
# Should see 3 PowerShell windows running
Get-Process python
```

**Linux**:
```bash
sudo systemctl status threatguard-agent
# Should show "active (running)"
```

### Test 2: Check Logs

**Windows**:
```powershell
Get-Content backend\logs\auto_block_monitor.log -Tail 10
Get-Content backend\logs\websocket_server.log -Tail 10
```

**Linux**:
```bash
tail -f /opt/threatguard_agent/logs/blocking_agent.log
# Should show "✅ Connected to WebSocket server"
```

### Test 3: Manual Block Test

1. Login to admin dashboard: http://localhost:3000
2. Navigate to threat management
3. Block any IP (e.g., 198.51.100.1)
4. Verify:
   - **Windows**: `netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"`
   - **Linux**: `sudo iptables -L THREATGUARD_BLOCK -n -v`

You should see the IP blocked on **BOTH** systems within seconds!

---

## 🎮 How to Use

### Automatic Blocking (Zero Effort)

Just leave it running! The system automatically:
1. Fetches threats every 2 minutes
2. Identifies high-risk IPs (score ≥ 75)
3. Blocks them on Windows
4. Sends command to Linux VM
5. Logs everything

Monitor with:
```powershell
Get-Content backend\logs\auto_block_monitor.log -Wait
```

### Manual Blocking (Admin Dashboard)

1. **Login**: http://localhost:3000
2. **Threats Page**: View all threats
3. **Click "Block IP"** on any threat
4. **Instant**: Blocked on Windows + Linux in < 1 second
5. **View Blocked IPs**: Admin → Blocked IPs

### Unblocking

1. **Admin Dashboard** → Blocked IPs
2. **Select IP** → Click "Unblock"
3. **Confirmed**: Removed from Windows + Linux

---

## 📊 What Gets Blocked?

### Automatic Blocking Criteria

| Condition | Action |
|-----------|--------|
| Risk Score ≥ 75 | **AUTO-BLOCK** |
| Severity = "High" | **AUTO-BLOCK** |
| Risk Score < 75 | Monitor only |

### Adjust Sensitivity

Edit `backend/.env`:
```env
AUTO_BLOCK_THRESHOLD=75   # Lower = more aggressive (e.g., 60)
AUTO_BLOCK_MAX_PER_CYCLE=5  # How many IPs per check
AUTO_BLOCK_CHECK_INTERVAL=120  # Seconds between checks
```

Restart services after changes.

---

## 🛠️ Common Issues & Fixes

### "Admin privileges required" on Windows

**Fix**: Restart PowerShell as Administrator
```powershell
# Right-click PowerShell → Run as Administrator
cd backend
python app.py
```

### VM agent "Connection refused"

**Fix 1**: Check Windows IP in agent_config.json
```bash
sudo nano /opt/threatguard_agent/agent_config.json
# Ensure websocket_url has correct Windows IP
```

**Fix 2**: Allow port 8765 on Windows firewall
```powershell
netsh advfirewall firewall add rule name="ThreatGuard_WS" dir=in action=allow protocol=TCP localport=8765
```

### "Permission denied" on Linux

**Fix**: Check sudo permissions
```bash
sudo -l  # Should show NOPASSWD for iptables
```

If not, re-run deployment:
```bash
sudo bash deploy_linux_vm.sh
```

---

## 📁 File Locations

### Windows

| File | Purpose |
|------|---------|
| `backend/app.py` | Main Flask API |
| `backend/websocket_server.py` | WebSocket server |
| `backend/auto_block_monitor.py` | Auto-blocking service |
| `backend/.env` | Configuration |
| `backend/logs/` | All log files |

### Linux

| File | Purpose |
|------|---------|
| `/opt/threatguard_agent/blocking_agent.py` | VM agent |
| `/opt/threatguard_agent/agent_config.json` | Configuration |
| `/opt/threatguard_agent/logs/` | Agent logs |
| `/opt/threatguard_agent/blocked_ips.json` | Blocked IPs list |

---

## 🔄 Restart Services

### Windows

```powershell
# Kill existing
Get-Process python | Stop-Process

# Restart
cd backend
.\start_all_services.ps1
```

### Linux

```bash
sudo systemctl restart threatguard-agent
```

---

## 📈 Monitor Activity

### Real-Time Monitoring

**Windows** (3 separate windows):
```powershell
# Window 1: Auto-blocking
Get-Content backend\logs\auto_block_monitor.log -Wait

# Window 2: WebSocket
Get-Content backend\logs\websocket_server.log -Wait

# Window 3: Sync operations
Get-Content backend\logs\blocking_sync.log -Wait
```

**Linux**:
```bash
# Watch agent activity
tail -f /opt/threatguard_agent/logs/blocking_agent.log

# Watch firewall in real-time
watch -n 2 'sudo iptables -L THREATGUARD_BLOCK -n -v'
```

### Check Blocked IPs

**Windows**:
```powershell
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"
```

**Linux**:
```bash
sudo iptables -L THREATGUARD_BLOCK -n -v
# or
cat /opt/threatguard_agent/blocked_ips.json | python3 -m json.tool
```

---

## 🎯 Next Steps

1. **Integrate Frontend**: Add `BlockingMonitor` component to admin dashboard
2. **Enable Notifications**: Browser notifications for new blocks
3. **Scale to Multiple VMs**: Deploy agent on additional VMs
4. **Production Hardening**: Switch to PostgreSQL, enable HTTPS/WSS
5. **Custom Rules**: Extend blocking logic for specific threat types

---

## 📞 Need Help?

1. **Check Logs** (Windows + Linux)
2. **Review** [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for detailed troubleshooting
3. **Verify** network connectivity between Windows and Linux
4. **Test** manually with API endpoints

---

## ✨ Success Indicators

You'll know it's working when you see:

✅ **Windows**:
- 3 PowerShell windows running (Backend, WebSocket, Auto-block)
- `[WS] INFO - VM Agent connected` in WebSocket logs
- `[AUTO-BLOCK] ✅ Successfully blocked` in auto-block logs

✅ **Linux**:
- `systemctl status threatguard-agent` shows "active (running)"
- `✅ Connected to WebSocket server` in agent logs
- Blocked IPs appear in iptables

✅ **Both**:
- Same IPs blocked on Windows firewall AND Linux iptables
- Block/unblock from dashboard syncs to VM within 1 second
- Logs show synchronized operations

---

**System Architecture**: Windows Host ↔ WebSocket ↔ Linux VM(s)  
**Blocking Time**: < 1 second for manual, < 2 minutes for automatic  
**Reliability**: Auto-reconnect, rollback on failure, persistent storage  

🎉 **You're now running a production-level, real-time, synchronized IP blocking system!**
