# ⚡ Real-Time Auto-Blocker Service - Complete Guide

## 🎯 Overview

The Real-Time Auto-Blocker is a **continuous background service** that monitors live threat feeds and automatically blocks high-risk IP addresses one by one with a 5-minute interval between blocks. Unlike the legacy cache-based blocker, this service:

✅ **Fetches live data** directly from OTX API (no cache dependency)  
✅ **Blocks threats one-by-one** with 5-minute intervals to avoid overwhelming the system  
✅ **Prevents duplicates** by tracking already-blocked IPs in the database  
✅ **Runs continuously** in a background thread  
✅ **Provides real-time status** updates to the admin dashboard  

---

## 🏗️ Architecture

### Backend Components

1. **`realtime_auto_blocker.py`** - Core service implementation
   - `RealtimeAutoBlocker` class - Main service logic
   - Runs in a background thread using Python's `threading` module
   - Fetches threats from OTX API every 60 seconds
   - Blocks one high-risk IP every 5 minutes
   - Tracks blocked IPs to prevent duplicates

2. **API Endpoints** (in `app.py`)
   - `POST /api/admin/realtime-blocker/start` - Start the service
   - `POST /api/admin/realtime-blocker/stop` - Stop the service
   - `GET /api/admin/realtime-blocker/status` - Get current status & statistics
   - `POST /api/admin/realtime-blocker/clear-queue` - Clear the threat queue

### Frontend Components

3. **AdminDashboard.js** - UI Controls & Status Display
   - Real-time status panel with statistics
   - Start/Stop service buttons
   - Queue preview showing next threats to block
   - Auto-refreshes every 10 seconds

---

## 🚀 How It Works

### Step-by-Step Process

```
1. Admin starts service from dashboard
   ↓
2. Service begins background thread
   ↓
3. Every 60 seconds:
   - Fetch latest threats from OTX API
   - Calculate risk score for each threat
   - Add high-risk threats (score ≥ 75) to queue
   - Skip already-blocked IPs
   ↓
4. Every 5 minutes:
   - Pop next threat from queue
   - Block IP at OS level (Windows Firewall/iptables)
   - Create database record in BlockedThreat table
   - Log action in ThreatActionLog
   - Update statistics
   ↓
5. Repeat steps 3-4 until service is stopped
```

### Risk Score Calculation

The service calculates a risk score (0-100) based on:

- **Base Score**: 50
- **High-Risk Tags** (+5 each): malware, ransomware, apt, exploit, botnet, phishing, c2
- **TLP Level**: Red (+20), Amber (+10)
- **Keywords in Description** (+8 each): ransomware, malware, exploit, botnet, c2, apt, etc.
- **Maximum**: Capped at 100

Only threats with **score ≥ 75** are added to the blocking queue.

---

## 🎮 Usage Instructions

### Starting the Service

1. **Navigate to Admin Dashboard**
   - Login as admin
   - Go to Admin Dashboard page

2. **Locate Real-Time Auto-Blocker Section**
   - Look for purple gradient section with "⚡ Real-Time Auto-Blocker Service" title

3. **Click "🚀 Start Live Blocking"**
   - Service will initialize and begin monitoring threats
   - Status indicator will change to "RUNNING" (green)

4. **Monitor Status**
   - View statistics: Total Blocked, Queue Size, Blocked IPs Count
   - See "Next block scheduled" time
   - Preview upcoming threats in queue

### Stopping the Service

1. **Click "🛑 Stop Service"** button
2. Confirm the action
3. Service will gracefully shut down
4. Status changes to "STOPPED"

### Clearing the Queue

If you want to reset the threat queue:
1. Click "🗑️ Clear Queue" button
2. Confirm the action
3. All queued threats are removed (already-blocked IPs remain blocked)

---

## 📊 Dashboard Features

### Status Panel

Shows real-time metrics:
- **Total Blocked**: Number of IPs blocked since service started
- **Queue Size**: Number of threats waiting to be blocked
- **Blocked IPs**: Total unique IPs currently blocked
- **Last Block**: Timestamp of most recent block action

### Queue Preview

Displays next 5 threats in queue:
- IP address (highlighted in yellow)
- Risk score (red badge)
- Pulse name (threat description)

### Service Information

Configuration details:
- Check Interval: 60 seconds (how often to fetch new threats)
- Block Interval: 300 seconds (5 minutes between blocks)
- Risk Threshold: ≥ 75 (minimum score to block)
- Service Started: When the service was last started

---

## 🔧 Configuration

### Environment Variables

Set these in your `.env` file:

```env
OTX_API_KEY=your_otx_api_key_here
```

### Customization Options

Edit `realtime_auto_blocker.py` to adjust:

```python
self.check_interval = 60      # Seconds between threat checks
self.block_interval = 300     # Seconds between blocks (5 minutes)
self.risk_threshold = 75      # Minimum score to block
```

---

## 🗄️ Database Schema

### BlockedThreat Table

Each blocked IP creates a record:
- `ip_address` - The blocked IP
- `blocked_by` - 'admin' (for auto-blocks)
- `blocked_by_user_id` - Admin who started the service
- `risk_score` - Calculated risk score
- `threat_type` - OTX pulse name
- `is_active` - True (until manually unblocked)

### ThreatActionLog Table

Each block action is logged:
- `action` - 'auto_block_realtime'
- `ip_address` - Blocked IP
- `performed_by_user_id` - Admin ID
- `details` - JSON with service info, score, pulse name, tags

---

## 🛡️ Security Features

1. **No Duplicates**: Checks database before blocking to prevent re-blocking same IPs
2. **Admin Only**: All endpoints require admin authentication
3. **Graceful Shutdown**: Service can be stopped safely without data loss
4. **Thread-Safe**: Uses locks to prevent race conditions
5. **Error Handling**: Continues running even if individual blocks fail

---

## 📝 API Reference

### Start Service
```http
POST /api/admin/realtime-blocker/start
Authorization: Bearer <admin_token>

Response:
{
  "message": "Real-time auto-blocker started successfully",
  "status": { ... }
}
```

### Stop Service
```http
POST /api/admin/realtime-blocker/stop
Authorization: Bearer <admin_token>

Response:
{
  "message": "Real-time auto-blocker stopped successfully",
  "status": { ... }
}
```

### Get Status
```http
GET /api/admin/realtime-blocker/status
Authorization: Bearer <admin_token>

Response:
{
  "initialized": true,
  "is_running": true,
  "status": "running",
  "total_blocked": 42,
  "queue_size": 15,
  "blocked_ips_count": 42,
  "last_block": "2026-02-12T10:30:00",
  "next_block_time": "2026-02-12T10:35:00",
  "queue": [
    {
      "ip": "203.0.113.42",
      "score": 87.5,
      "pulse_name": "Ransomware Campaign",
      "tags": ["ransomware", "malware"]
    }
  ],
  "check_interval": 60,
  "block_interval": 300,
  "risk_threshold": 75
}
```

### Clear Queue
```http
POST /api/admin/realtime-blocker/clear-queue
Authorization: Bearer <admin_token>

Response:
{
  "message": "Cleared 15 threats from queue",
  "cleared_count": 15,
  "status": { ... }
}
```

---

## 🐛 Troubleshooting

### Service Won't Start

**Issue**: Error when clicking "Start Service"  
**Solution**: 
- Check backend logs: `backend/logs/realtime_auto_blocker.log`
- Ensure OTX_API_KEY is set in `.env`
- Verify admin user has proper permissions

### No Threats Being Blocked

**Issue**: Service running but queue is empty  
**Solution**:
- Check OTX API connectivity
- Verify API key is valid
- Threats may not meet risk threshold (≥75)
- Check backend logs for OTX API errors

### Duplicate Blocks

**Issue**: Same IP being blocked multiple times  
**Solution**: Should not happen - service checks database. If it does:
- Check database connection
- Verify BlockedThreat table is being updated
- Review logs for errors during block process

### Service Stops Unexpectedly

**Issue**: Service status shows "STOPPED" without manual stop  
**Solution**:
- Check backend logs for exceptions
- Verify database connection is stable
- Check for OTX API rate limiting

---

## 📈 Performance Considerations

- **Memory Usage**: ~20-50 MB depending on queue size
- **CPU Usage**: Minimal (sleeps most of the time)
- **Network**: One API call every 60 seconds to OTX
- **Database**: One insert every 5 minutes per block

### Recommended Limits

- Maximum queue size: 100 threats (auto-managed)
- Monitor for >1000 threats/day (may indicate misconfiguration)
- Review blocked IPs weekly to prevent false positives

---

## 🔄 Difference from Legacy Auto-Blocker

| Feature | Legacy Auto-Blocker | Real-Time Auto-Blocker |
|---------|---------------------|------------------------|
| Data Source | Cache file (recent_threats.json) | Live OTX API |
| Execution | On-demand (manual trigger) | Continuous background service |
| Blocking Rate | All at once | One every 5 minutes |
| Duplicate Prevention | Basic check | Database-backed tracking |
| Status Updates | None | Real-time dashboard |
| Control | Manual trigger only | Start/Stop/Monitor |

---

## ✅ Testing Checklist

- [ ] Service starts successfully
- [ ] Status updates appear in dashboard
- [ ] Queue populates with threats
- [ ] First IP blocks within 5 minutes
- [ ] Subsequent IPs block at 5-minute intervals
- [ ] No duplicate blocks occur
- [ ] Service stops when requested
- [ ] Queue clears when requested
- [ ] Database records created correctly
- [ ] Dashboard auto-refreshes every 10 seconds

---

## 📞 Support

For issues or questions:
1. Check logs: `backend/logs/realtime_auto_blocker.log`
2. Review database: `BlockedThreat` and `ThreatActionLog` tables
3. Verify OTX API connectivity
4. Check admin dashboard console for errors

---

## 🎉 Summary

The Real-Time Auto-Blocker provides **continuous, intelligent threat protection** by:
- ⚡ Monitoring live threat feeds in real-time
- 🎯 Blocking high-risk IPs automatically
- 🔄 Operating continuously in the background
- 📊 Providing transparent status updates
- 🛡️ Preventing duplicate blocks
- ⏱️ Controlling blocking rate to avoid system overload

Perfect for **24/7 threat protection** with full admin visibility and control!
