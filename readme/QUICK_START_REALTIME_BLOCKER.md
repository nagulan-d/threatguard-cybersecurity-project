# 🚀 Quick Start - Real-Time Auto-Blocker

## Prerequisites

1. ✅ Backend running: `python backend/app.py`
2. ✅ Frontend running: `npm start` (in frontend folder)
3. ✅ Admin account created and logged in
4. ✅ OTX API key set in `.env` file

---

## Starting the Service (3 Simple Steps)

### Step 1: Login as Admin
```
1. Go to http://localhost:3000
2. Login with admin credentials
3. Click "Admin Dashboard"
```

### Step 2: Find the Auto-Blocker Section
```
Scroll down to the purple gradient section:
┌──────────────────────────────────────────────┐
│ ⚡ Real-Time Auto-Blocker Service   [STOPPED] │
│                                              │
│ 🎯 Live Threat Monitoring: Fetches threats  │
│    directly from OTX API...                  │
│                                              │
│ [🚀 Start Live Blocking]                     │
└──────────────────────────────────────────────┘
```

### Step 3: Start the Service
```
1. Click "🚀 Start Live Blocking"
2. Confirm the alert
3. Watch the status change to "RUNNING" (green)
```

---

## What Happens Next?

### Immediately (0-10 seconds)
- ✅ Service initializes
- ✅ Loads already-blocked IPs from database
- ✅ Status shows "RUNNING"

### First Minute (0-60 seconds)
- 🔍 Fetches live threats from OTX API
- 📊 Calculates risk scores
- ➕ Adds high-risk threats to queue

### After 1 Minute
- 📋 Queue preview shows upcoming threats
- ⏰ "Next block scheduled" appears
- 📈 Statistics start updating

### First Block (Within 5 minutes)
- 🛡️ First IP from queue gets blocked
- ✅ Database record created
- 📝 Action logged
- 🔄 Statistics update

### Continuous Operation
- Every 60 seconds: Check for new threats
- Every 5 minutes: Block next IP in queue
- Every 10 seconds: Dashboard refreshes automatically

---

## Monitoring the Service

### Dashboard Statistics

Watch these metrics update:

```
┌─────────────────────────────────────────────┐
│ Total Blocked: 0 → 1 → 2 → 3 ...           │
│ Queue Size: 15 → 14 → 13 ...               │
│ Blocked IPs: 0 → 1 → 2 → 3 ...             │
│ Last Block: Never → 10:30:05 AM            │
└─────────────────────────────────────────────┘
```

### Queue Preview

See what's coming next:

```
📋 Threat Queue (Next 5 threats)
┌────────────────────────────────────┐
│ 203.0.113.42         [87.5] 🔴    │
│ Ransomware Campaign                │
├────────────────────────────────────┤
│ 198.51.100.17        [82.0] 🔴    │
│ Malware Distribution Network       │
└────────────────────────────────────┘
```

---

## Testing the Blocking

### Verify Blocked IPs

1. **Check Database**:
```sql
SELECT ip_address, risk_score, blocked_at 
FROM blocked_threat 
WHERE blocked_by = 'admin' 
ORDER BY blocked_at DESC 
LIMIT 10;
```

2. **Check Firewall** (Windows PowerShell):
```powershell
Get-NetFirewallRule | Where-Object {$_.DisplayName -match "ThreatGuard"}
```

3. **Check Admin Dashboard**:
- Scroll to "🛡️ Auto-Blocked High-Risk Threats" section
- Should see newly blocked IPs appearing

---

## Manual Testing

### Force Immediate Check

1. Click "🔄 Refresh Status"
2. Check backend console for:
```
🔍 Fetching live threats from OTX API...
✅ Fetched 50 pulses from OTX
📊 Extracted 123 IP indicators from pulses
➕ Added to queue: 203.0.113.42 (score=87.5, queue_size=15)
```

### Check Logs

```powershell
# View real-time logs
Get-Content backend/logs/realtime_auto_blocker.log -Wait -Tail 20
```

You should see:
```
🚀 RealtimeAutoBlocker initialized
🎯 Service loop started
📚 Loaded 0 already-blocked IPs from database
🔄 Checking for new threats...
🔍 Fetching live threats from OTX API...
✅ Fetched 50 pulses from OTX
➕ Added to queue: 203.0.113.42 (score=87.5, queue_size=1)
⏰ Next block in 300 seconds
🛡️ BLOCKING: 203.0.113.42 (score=87.5)
✅ Successfully blocked 203.0.113.42
```

---

## Stopping the Service

### Graceful Shutdown

1. Click "🛑 Stop Service"
2. Confirm the action
3. Service stops cleanly
4. Status changes to "STOPPED"

**Note**: Already-blocked IPs remain blocked even after stopping the service.

---

## Clearing the Queue

If you want to reset:

1. Click "🗑️ Clear Queue"
2. Confirm the action
3. Queue empties (blocked IPs remain blocked)

---

## Common Issues & Solutions

### Issue: Queue is Empty

**Possible Causes**:
- No high-risk threats available
- All threats already blocked
- OTX API rate limiting

**Solution**:
- Wait a few minutes for new threats
- Check OTX API key is valid
- Review logs for API errors

### Issue: Blocks Not Happening

**Check**:
1. Service status is "RUNNING" (green)
2. Queue has threats (Queue Size > 0)
3. "Next block scheduled" shows future time
4. Check logs for errors

**Triggers**:
- First block happens within 5 minutes of start
- Subsequent blocks every 5 minutes

### Issue: Service Won't Start

**Check**:
1. Backend is running
2. Admin logged in
3. OTX_API_KEY in `.env`
4. Database connection working

**Debug**:
```powershell
# Check backend console
python backend/app.py

# Should see:
# Flask app is running on http://0.0.0.0:5000
```

---

## Expected Behavior Timeline

```
Time    Event
─────── ────────────────────────────────────────
00:00   Click "Start Service"
00:01   Status → RUNNING
00:10   Queue populated with threats
00:15   Statistics show queue size
05:00   First IP blocked
10:00   Second IP blocked
15:00   Third IP blocked
...     One IP every 5 minutes
```

---

## Verification Steps

✅ **Service Started**
- Status indicator shows "RUNNING" (green with pulsing dot)

✅ **Threats Queued**
- Queue Size > 0
- Queue preview shows IPs and scores

✅ **Blocking Works**
- Total Blocked counter increases
- Last Block timestamp updates
- New entries in "Auto-Blocked Threats" section below

✅ **No Duplicates**
- Same IP never appears in queue twice
- Blocked IPs count matches unique IPs

✅ **Continuous Operation**
- Service keeps running
- Queue refills as threats are processed
- Statistics update automatically

---

## Performance Benchmarks

**Normal Operation**:
- Queue size: 5-50 threats
- Blocks per hour: ~12 (one every 5 minutes)
- Blocks per day: ~288 (maximum)

**Resource Usage**:
- CPU: <5%
- Memory: ~30 MB
- Network: ~1 KB/min (OTX API calls)

---

## Next Steps

After the service is running:

1. **Monitor for 30 minutes** - Verify blocks happen every 5 minutes
2. **Check blocked IPs** - Review auto-blocked threats section
3. **Test stop/start** - Ensure service survives restarts
4. **Review logs** - Check for any errors or warnings
5. **Verify firewall** - Confirm OS-level blocks are active

---

## Success Indicators

You'll know everything is working when:

1. ✅ Status shows "RUNNING" continuously
2. ✅ Queue populates with 5-20 threats
3. ✅ First block happens within 5 minutes
4. ✅ Subsequent blocks happen every 5 minutes
5. ✅ No duplicate IPs in queue or blocks
6. ✅ Statistics update in real-time
7. ✅ "Auto-Blocked Threats" table grows
8. ✅ Logs show successful operations

---

## Tips for Best Results

🎯 **Leave It Running**: Service works best when running continuously

🔍 **Monitor Initially**: Watch for first hour to ensure proper operation

📊 **Check Statistics**: Should see steady blocking rate (1 per 5 min)

🛡️ **Review Blocks**: Periodically check auto-blocked threats

🔄 **Restart Daily**: Optional - keeps queue fresh

---

## Emergency Stop

If you need to stop immediately:

1. Dashboard: Click "🛑 Stop Service"
2. Backend: Ctrl+C to stop Flask app
3. Firewall: Manually remove rules if needed

**Note**: Already-blocked IPs remain blocked until manually unblocked.

---

## Support & Logs

**Backend Logs**:
- `backend/logs/realtime_auto_blocker.log` - Service events
- `backend/backend_log.txt` - General backend logs

**Database Tables**:
- `blocked_threat` - All blocked IPs
- `threat_action_log` - Blocking actions

**Browser Console**:
- F12 → Console tab - Frontend errors/logs

---

🎉 **You're all set!** The real-time auto-blocker is now protecting your system 24/7!
