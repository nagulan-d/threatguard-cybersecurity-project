# 🎯 Admin Dashboard Auto-Blocking - Quick Reference

## What Changed

✅ **Admin dashboard now shows at least 15 threats**  
✅ **Guaranteed minimum 5 high-severity threats (score >= 75)**  
✅ **Auto-blocks high threats ONE BY ONE with delays**  

---

## How It Works

```
Admin Dashboard Loads
         ↓
Fetches min 15 threats (at least 5 high-risk)
         ↓
Displays threats on screen
         ↓
System detects high-risk threats (score >= 75)
         ↓
AUTO-BLOCKING STARTS (after 2 seconds)
         ↓
Blocks 1st high threat → Wait 10s
         ↓
Blocks 2nd high threat → Wait 10s
         ↓
... continues until 5 threats blocked or no more to block
         ↓
Alert shows blocked IPs
         ↓
Process repeats every 5 minutes
```

---

## Testing Now

### 1. Ensure you have threats:
```powershell
cd backend
python fetch_realtime_threats.py --limit 50 --modified_since 24h
```

### 2. Start backend:
```powershell
python app.py
```

### 3. Start frontend:
```powershell
cd ..\frontend
npm start
```

### 4. Login as admin:
- Go to http://localhost:3000
- Login with admin account
- Navigate to Admin Dashboard

### 5. Watch for:
- **15 threats displayed** (not less)
- **At least 5 marked as "High" severity**
- **Console message**: "🛡️ X high-risk threats detected - initiating one-by-one auto-blocking..."
- **Backend blocking** one threat every 10 seconds
- **Success alert** with list of blocked IPs

---

## Configuration (.env)

```env
AUTO_BLOCK_DELAY=10            # Seconds between each block
AUTO_BLOCK_MAX_PER_CYCLE=5     # Max threats to block per cycle
AUTO_BLOCK_THRESHOLD=75        # Minimum score for auto-blocking
```

---

## Expected Behavior

### ✅ What You'll See:

**Browser Console:**
```
[ADMIN] Fetched 15 threats with 7 high-severity
🛡️ 7 high-risk threats detected - initiating one-by-one auto-blocking...
Found 7 high-risk threats to block
✅ Auto-block response: {...}
```

**Backend Console:**
```
[ADMIN] Returning 15 threats with 7 high-severity (min: 5)
[BLOCKING 1/5] 🔒 192.168.1.100 (Score: 85)
✅ [BLOCK] Blocked IP 192.168.1.100 globally
⏳ Waiting 10s before next block...
[BLOCKING 2/5] 🔒 192.168.1.101 (Score: 82)
...
```

**Success Alert:**
```
✅ Successfully auto-blocked 5 high-risk threat(s) this cycle!

Blocked IPs:
  • 192.168.1.100 (Score: 85)
  • 192.168.1.101 (Score: 82)
  • 192.168.1.102 (Score: 80)
  • 192.168.1.103 (Score: 78)
  • 192.168.1.104 (Score: 77)
```

---

## Manual Trigger

In admin dashboard, click **"🔄 Scan & Block Now"** button to manually trigger auto-blocking anytime.

---

## Verification

**Check that threats are blocked:**
- Scroll to "🛡️ Auto-Blocked High-Risk Threats" section in admin dashboard
- Look for newly blocked IPs with "Admin" in blocked_by column
- Check timestamps are recent

---

## Troubleshooting

**Problem:** Less than 15 threats shown
- **Solution:** Run `python fetch_realtime_threats.py --limit 50 --modified_since 24h`

**Problem:** Less than 5 high-severity threats
- **Solution:** Fetch more threats or use longer time range (--modified_since 7d)

**Problem:** No auto-blocking happening
- **Check:** Browser console for any errors
- **Check:** Backend console shows auto-block messages
- **Check:** AUTO_BLOCK_ENABLED=true in .env

**Problem:** Already blocked message
- **Expected:** System won't re-block IPs that were already blocked
- **Solution:** Deactivate old blocks if you want to test re-blocking

---

## Quick Stats

| Feature | Value |
|---------|-------|
| Min threats shown | 15 |
| Min high-severity | 5 |
| Block delay | 10 seconds |
| Max per cycle | 5 threats |
| Auto-repeat interval | 5 minutes |
| Trigger on load | Yes (2s delay) |

---

## Files Changed

- ✅ `backend/app.py` - Enhanced threat fetching and auto-blocking
- ✅ `frontend/src/components/AdminDashboard.js` - Added admin parameter and auto-blocking trigger
- ✅ `backend/ADMIN_DASHBOARD_AUTO_BLOCKING.md` - Full documentation
- ✅ `backend/ADMIN_DASHBOARD_QUICK_REFERENCE.md` - This file

---

**Ready to use!** Just restart your backend and login as admin. The system will automatically show 15+ threats with at least 5 high-risk ones, and block them one by one as they appear.
