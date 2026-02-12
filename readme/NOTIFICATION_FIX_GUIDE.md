# 🔔 Automatic Threat Notifications - Quick Fix Guide

## ❓ Why Notifications Aren't Working

The automatic notification system requires **3 things** to work:

1. ✅ **User must be subscribed** to threat notifications
2. ✅ **High-risk threats exist** in the cache (score >= 75)
3. ✅ **Email is configured** in .env file

## 🚀 Quick Fix Steps

### Step 1: Subscribe Admin to Notifications

**Option A: Run the Helper Script**
```powershell
cd backend
.\ENABLE_NOTIFICATIONS.ps1
```

**Option B: Via Dashboard**
1. Login as admin
2. Go to Settings/Profile
3. Enable "Threat Email Notifications"
4. Save settings

### Step 2: Check Notification System

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python check_notifications.py
```

This will show you:
- ✅ If users are subscribed
- ✅ If high-risk threats exist
- ✅ If email is configured
- ✅ Recent notification logs

### Step 3: Restart Backend

After subscribing, restart the backend to start the notification cycle:
```powershell
# Stop backend (Ctrl+C)
# Then restart as admin:
.\START_BACKEND_ADMIN.ps1
```

## 🔍 How to Verify It's Working

### 1. Check Backend Console

After restart, you should see:
```
============================================================
🚀 STARTING THREATGUARD BACKEND
============================================================
✅ Cache updater thread started
✅ Background threat notification processor started
📧 Automatic notifications enabled (every 2 minutes)
============================================================
```

### 2. Wait for First Cycle (2 minutes)

You'll see logs like:
```
============================================================
[BACKGROUND] [2026-02-12 10:30:00] Notification cycle #1
============================================================
[BACKGROUND] Active subscriptions: 1
  - admin (admin@email.com) - min_risk_score: 75.0
[BACKGROUND] ✅ Loaded 30 cached threats
[BACKGROUND] High-risk threats (score >= 75): 5
[BACKGROUND] IP-based high-risk threats: 3
[BACKGROUND] 📧 Processing notifications...
[NOTIFY] Sent alert to admin (free) for IP 1.2.3.4
```

## 📊 What Triggers a Notification?

Notifications are sent when:
- ✅ User is **subscribed** and **active**
- ✅ Threat has **risk score >= 75** (high-risk)
- ✅ Threat has a **valid IP address**
- ✅ Threat **hasn't been notified** in last 24 hours
- ✅ IP is **not already blocked** by that user

## ⏰ Notification Schedule

- **Interval**: Every **2 minutes** (changed from 5 minutes)
- **Scope**: Only high-risk threats (score >= 75)
- **Frequency**: Once per threat per user per 24 hours

## 🔧 Troubleshooting

### Problem: "No active subscriptions found"

**Solution**: Run `.\ENABLE_NOTIFICATIONS.ps1` or subscribe via dashboard

### Problem: "No high-risk threats"

**Cause**: This is normal! It means there are currently no high-risk threats detected.

**Check**: Run `python check_notifications.py` to see threat count

### Problem: "Email failed"

**Check .env file**:
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

**Note**: For Gmail, you need an **App Password**, not your regular password:
1. Go to Google Account Settings
2. Security → 2-Step Verification
3. App Passwords → Generate new password
4. Copy password to .env

### Problem: Background thread not starting

**Check**: Backend logs should show:
```
✅ Background threat notification processor started
```

If not shown, the thread didn't start. Make sure:
- Backend running with `debug=False` (default)
- No errors during startup

## 📧 Test Notification Manually

You can test email sending without waiting:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -c "from app import app, mail; from flask_mail import Message; app.app_context().push(); msg = Message('Test', recipients=['your@email.com'], body='Test notification'); mail.send(msg); print('✅ Email sent!')"
```

## 📝 Quick Commands

```powershell
# Enable notifications for admin
.\ENABLE_NOTIFICATIONS.ps1

# Check notification status
python check_notifications.py

# Start backend with notifications
.\START_BACKEND_ADMIN.ps1

# View notification logs in real-time
# Just watch the backend console after starting
```

## ✅ Success Checklist

- [ ] Admin user subscribed to notifications (`.\ENABLE_NOTIFICATIONS.ps1`)
- [ ] Email configured in .env with valid credentials
- [ ] Backend started and shows "Background threat notification processor started"
- [ ] Wait 2 minutes for first notification cycle
- [ ] Check backend console for "[BACKGROUND]" messages
- [ ] If high-risk threats exist, notifications should be sent

## 🎯 Expected Behavior

Once everything is set up:

1. **Every 2 minutes**, the background thread wakes up
2. It loads threats from cache
3. Filters for high-risk threats (score >= 75) with valid IPs
4. Checks each subscribed user
5. Sends email for new threats that haven't been notified in 24h
6. Logs the notification in database
7. Sleeps for 2 minutes and repeats

---

**For detailed diagnostic information, run:**
```powershell
python check_notifications.py
```
