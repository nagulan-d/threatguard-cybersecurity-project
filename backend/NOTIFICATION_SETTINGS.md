# 🔔 Automatic Notification Settings

## Current Configuration

### ⏰ Check Interval: **1 MINUTE**
- System checks for new high-risk threats every **60 seconds**
- Sends immediate alerts when high-risk IP threats are detected in dashboard

### 📧 Notification Rules
- **Risk Threshold**: Score >= 75 (High-risk only)
- **Threat Type**: IP-based threats only (for auto-blocking capability)
- **Cooldown**: 1 hour between notifications for same IP
- **Recipients**: All subscribed users

### 🎯 How It Works
1. **Every 1 minute**, background thread wakes up
2. Loads current threats from cache (`recent_threats.json`)
3. Filters for high-risk IP threats (score >= 75)
4. Sends email notifications to all subscribed users
5. Waits for next dashboard refresh to get fresh threats

## Console Output
Watch for these logs (appear every 60 seconds):
```
============================================================
[BACKGROUND] [2026-02-12 14:30:00] Notification cycle #1
============================================================
[BACKGROUND] Active subscriptions: 1
  - admin (admin@example.com) - min_risk_score: 75.0
[BACKGROUND] ✅ Loaded 30 cached threats
[BACKGROUND] High-risk threats (score >= 75): 12
[BACKGROUND] IP-based high-risk threats: 8
[BACKGROUND] 📧 Processing notifications...
[NOTIFY] Processing 30 threats for 1 subscribed users
[NOTIFY] 8 IP-based high-risk threats eligible for automated alerts
[NOTIFY] ✅ Sent alert to admin (premium) for IP 198.51.100.42
[NOTIFY] 📧 Sent 1 total notifications this cycle
[BACKGROUND] Cycle #1 complete
[BACKGROUND] ⏰ Sleeping 60s (1 minute) until next cycle...
============================================================
```

## Subscribe to Notifications

Run this PowerShell script to enable notifications:
```powershell
.\ENABLE_NOTIFICATIONS.ps1
```

Or manually create subscription via API:
```bash
curl -X POST http://127.0.0.1:5000/api/notifications/subscribe \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "min_risk_score": 75}'
```

## Change Interval

To modify the check interval, edit `.env` file:
```env
THREATS_POLL_INTERVAL=60  # seconds (60 = 1 minute, 120 = 2 minutes, etc.)
```

## Premium vs Free Users

### Premium Users
- Get detailed threat emails with blocking links
- Can block IPs directly from email
- Receive full threat analysis

### Free Users  
- Get brief threat alerts
- Directed to dashboard for details
- No IP blocking capability

---

**Note**: Backend must be restarted as Administrator for IP blocking to work with Windows Firewall.
