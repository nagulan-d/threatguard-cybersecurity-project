# 📧 Email-Based IP Blocking System - Complete Guide

**Status**: ✅ PRODUCTION READY  
**Date**: January 28, 2026  
**Feature**: User-Initiated IP Blocking via Email  

---

## 🎯 Overview

The Email-Based IP Blocking system enables users to block malicious IP addresses directly from their email inbox. When a high-risk threat is detected, ThreatGuard automatically sends a secure email notification containing a "Block IP" button. Clicking this button triggers an instant, secure block action on the user's environment without requiring authentication.

**Key Components:**
- Automated threat email notifications (existing)
- Secure one-time-use block tokens (BlockToken model)
- Email verification endpoint (`/api/user/block-threat`)
- User dashboard "Blocked IPs" tab
- Admin notifications of user actions
- Audit trail logging

---

## 🔄 Complete Workflow

### Phase 1: Threat Detection & Email Generation
1. **Threat Fetcher**: AlienVault OTX API detects threats
2. **Cache Population**: Threats stored in `recent_threats.json`
3. **Background Processor**: Scans for high-risk threats (score ≥ 75)
4. **Email Filter**: Checks subscription settings and prevents duplicates
5. **Token Generation**: Creates unique, one-time-use token (24-hour expiry)
6. **Email Send**: Sends HTML email with "Block IP" button containing secure link

### Phase 2: User Clicks Email Button
1. **Email Link Click**: User opens email and clicks "Block IP"
2. **Frontend Route**: Browser navigates to `/block-threat?token=xyz`
3. **Processing Page**: BlockThreatEmail component processes the request
4. **Validation**: Token checked for validity, expiration, prior use

### Phase 3: Block Execution
1. **Token Verification**: Validates token exists, not expired, not used
2. **IP Validation**: Confirms IP format (IPv4/IPv6) is correct
3. **Duplicate Check**: Prevents re-blocking same IP
4. **Database Record**: Creates BlockedThreat (blocked_by='user')
5. **Action Log**: Records action in ThreatActionLog for audit
6. **Token Marked**: Sets token as used to prevent reuse
7. **Firewall Block**: Calls `ip_blocker.block_ip()` to actually block IP
8. **Admin Notify**: Creates AdminNotification for all admin users
9. **Confirmation Email**: Sends success confirmation to user

### Phase 4: Real-Time Feedback
1. **Frontend Feedback**: Displays success/error page with details
2. **Dashboard Update**: User navigates to see blocked IP in "Blocked IPs" tab
3. **Admin Dashboard**: Admins see notification of user action
4. **Audit Trail**: Complete record in database for compliance

---

## 🔐 Security Model

### Token Security
- **Generation**: `secrets.token_urlsafe(32)` - cryptographically secure
- **Storage**: Stored in `BlockToken` table in SQLite database
- **Expiration**: 24-hour validity window
- **One-Time Use**: Marked as `is_used=True` after first use
- **No Authentication Required**: Token itself is the security credential

### IP Validation
- **IPv4 Format**: Regex pattern + range validation (0.0.0.0 to 255.255.255.255)
- **IPv6 Format**: Standard IPv6 validation
- **Extraction**: From multiple possible fields (ip, ip_address, indicator)
- **Invalid Handling**: Rejected with detailed error message

### Duplicate Prevention
- **Query Check**: `BlockedThreat.query.filter_by(user_id, ip_address, is_active=True, blocked_by='user')`
- **User-Scoped**: Each user can block same IP independently
- **Unblock Support**: Users can unblock and re-block if needed

### Authorization
- **No Login Required**: Email token validates identity
- **IP Extraction**: Token contains user_id, verified before processing
- **Admin Separation**: Only user-initiated blocks shown in user dashboard
- **Role Isolation**: Users can only unblock their own blocks

---

## 🔌 API Endpoints

### POST `/api/user/block-threat`
**Purpose**: Process email-based block request  
**Authentication**: Token-based (no Bearer token)  
**Parameters**:
```json
{
  "token": "secure_token_from_email_link"
}
```

**Response (Success)**:
```json
{
  "message": "IP 192.168.1.1 has been successfully blocked",
  "success": true,
  "ip_address": "192.168.1.1",
  "threat_type": "Ransomware",
  "risk_score": 87,
  "blocked_by": "user",
  "blocked_at": "2026-01-28T10:30:45.123456",
  "username": "john_user"
}
```

**Response (Already Blocked)**:
```json
{
  "message": "IP was already blocked by you",
  "already_blocked": true,
  "ip_address": "192.168.1.1",
  "blocked_at": "2026-01-28T10:00:00.000000"
}
```

**Error Responses**:
- `400`: No token / Invalid IP format
- `403`: Token expired / Already used
- `404`: Token not found / User not found
- `500`: Server error

---

### GET `/api/user/blocked-threats`
**Purpose**: Retrieve all IPs blocked by current user  
**Authentication**: JWT Bearer token required  
**Parameters**:
- `is_active` (optional): `true` or `false` to filter active/inactive

**Response**:
```json
{
  "count": 5,
  "active": 4,
  "blocked_threats": [
    {
      "id": 123,
      "ip_address": "192.168.1.1",
      "threat_type": "Ransomware",
      "risk_category": "High",
      "risk_score": 87,
      "summary": "Blocked via email alert by user action",
      "reason": "User-initiated block from email alert (score 87)",
      "is_active": true,
      "blocked_at": "2026-01-28T10:30:45.123456",
      "unblocked_at": null
    }
  ]
}
```

---

### POST `/api/user/unblock-threat/<threat_id>`
**Purpose**: Unblock an IP previously blocked by user  
**Authentication**: JWT Bearer token required  
**Parameters**: threat_id in URL path

**Response**:
```json
{
  "message": "IP 192.168.1.1 has been unblocked",
  "ip_address": "192.168.1.1",
  "unblocked_at": "2026-01-28T10:45:30.000000"
}
```

---

## 📊 Database Models

### BlockToken
```python
id                  (Primary Key)
token               (String, unique, indexed) - secure token
user_id             (Foreign Key) - recipient user
ip_address          (String) - IP to be blocked
threat_type         (String) - type of threat
risk_score          (Float) - threat risk score
is_used             (Boolean) - has token been used?
created_at          (DateTime, indexed) - creation time
expires_at          (DateTime, indexed) - 24 hours from creation
used_at             (DateTime) - when token was used
```

### BlockedThreat (modified usage)
```python
blocked_by          (String) - 'user' or 'admin'
user_id             (Integer) - who owns this block
blocked_by_user_id  (Integer) - who performed the block
reason              (String) - why it was blocked
is_active           (Boolean) - block still active?
blocked_at          (DateTime) - when blocked
unblocked_at        (DateTime) - when unblocked (if applicable)
unblocked_by_user_id(Integer) - who unblocked it
```

### ThreatActionLog (modified usage)
```python
action              (String) - 'block_email_link' for email blocks
details             (JSON) - {threat_type, risk_score, via, token_id}
```

### AdminNotification (used for user actions)
```python
notification_type   (String) - 'user_action_block'
title               (String) - "User X Blocked IP"
related_user_id     (Integer) - which user took the action
```

---

## 🖥️ Frontend Components

### BlockThreatEmail.js
**Location**: `frontend/src/components/BlockThreatEmail.js`  
**Purpose**: Process and display block action result  
**Features**:
- Extracts token from URL query params
- Sends block request to backend
- Shows 4 possible states: processing, success, already_blocked, error
- Displays threat details (IP, type, score, timestamp)
- Provides action buttons and next steps
- Animated transitions for better UX

**States**:
- **Processing**: Spinner, loading message
- **Success**: Green checkmark, threat details, navigate button
- **Already Blocked**: Warning icon, previous block info
- **Error**: Red X, error message, troubleshooting tips, retry button

---

### UserDashboard.js (Enhanced)
**Location**: `frontend/src/components/UserDashboard.js`  
**New Features**:
- Added `blockedThreats` state variable
- Added `fetchUserBlocks()` function
- Added `handleUnblockIP()` function
- Added tab navigation system
- Added "Blocked IPs" tab (activeTab === 'blocked')
- Tab buttons: Overview, Websites, Alerts, Blocked IPs

**Blocked IPs Tab**:
- Shows all user-blocked IPs
- Color-coded risk scores (Red ≥75, Orange 50-74, Yellow <50)
- Status indicators (🟢 Active, ⚫ Inactive)
- Unblock button for active blocks
- Displays IP, type, score, category, reason, timestamp

---

## 📧 Email Templates

### Threat Alert Email
**Subject**: "⚠️ Threat Detected"  
**Features**:
- Color-coded header (RED for High, ORANGE for Medium, YELLOW for Low)
- IP address display in monospace font
- Threat type, risk score, summary
- Large "Block IP" button with gradient color
- Premium: Expanded prevention guide and steps
- Free: Upgrade prompt
- Footer with unsubscribe link

**Block Button**:
```html
<a href="https://frontend.url/block-threat?token=xyz">
  Block This IP
</a>
```

### Confirmation Email
**Subject**: "✅ IP Successfully Blocked"  
**Features**:
- Green header with success message
- IP address and block timestamp
- Confirmation that IP is blocked
- Link to manage in dashboard
- Professional footer

---

## 🔔 Notification Flow

### User Notifications
1. **Threat Alert Email**: Sent automatically when high-risk threat detected
2. **Confirmation Email**: Sent after user clicks "Block IP"
3. **Dashboard Updates**: Real-time updates when navigating to "Blocked IPs"

### Admin Notifications
1. **User Action Alert**: AdminNotification created when user blocks IP
2. **Dashboard Notification**: Appears in Admin Dashboard
3. **Audit Log**: Recorded in ThreatActionLog for compliance

---

## 🚀 Usage Examples

### User Workflow
1. User receives email about ransomware threat (IP 192.168.1.1, score 92)
2. User clicks "Block IP" button in email
3. Browser opens `/block-threat?token=abc123def456`
4. BlockThreatEmail component processes request
5. Backend validates token, creates database records, blocks IP
6. Success page displays with IP and confirmation
7. User navigates to dashboard to see "Blocked IPs" tab
8. IP appears in list with "🟢 Active" status

### Admin Workflow
1. Admin checks Admin Dashboard
2. Sees notification: "User john_user blocked IP 192.168.1.1"
3. Can view all user-blocked IPs in admin panel
4. Can unblock globally if needed (separate endpoint)
5. Full audit trail available in database

### Unblock Workflow
1. User navigates to "Blocked IPs" tab
2. Finds previously blocked IP
3. Clicks "Unblock IP" button
4. Confirms action in dialog
5. IP marked as inactive
6. Removed from active list (can re-block later)
7. Action logged in audit trail

---

## ⚙️ Configuration

### Environment Variables
```
FRONTEND_URL=http://localhost:3000
MAIL_SERVER_HOST=smtp.gmail.com
MAIL_SERVER_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Token Expiration
- Default: 24 hours
- Located in: `email_service.py`, line: `expires_at=datetime.utcnow() + timedelta(hours=24)`
- Change by modifying timedelta hours value

### Risk Score Threshold for Emails
- Default: ≥ 75 (HIGH risk only)
- Located in: `app.py`, `_send_threat_notifications()` function
- Query: `high_risk_threats = [t for t in threats if t.get("score", 0) >= 75]`

### Duplicate Prevention
- Same user cannot block same IP twice (unless unblocked first)
- Different users can block same IP independently
- Admin blocks don't interfere with user blocks

---

## 📊 Monitoring & Logging

### Console Logs
All operations include `[EMAIL-BLOCK]` prefix for easy filtering:

```
🔓 [EMAIL-BLOCK] Validating block token...
✅ [EMAIL-BLOCK] Token valid for user john_user, IP 192.168.1.1
❌ [EMAIL-BLOCK] Invalid IP format: invalid_ip
⚠️  [EMAIL-BLOCK] IP already blocked by user john_user: 192.168.1.1
✅ [EMAIL-BLOCK] Database records created for user john_user
✅ [EMAIL-BLOCK] IP 192.168.1.1 blocked successfully
✅ [EMAIL-BLOCK] Confirmation email sent to john@example.com
```

### Database Audit Trail
All actions stored in `ThreatActionLog`:
- `action`: 'block_email_link'
- `user_id`: User who took action
- `ip_address`: IP that was blocked
- `details`: JSON with threat info and token reference
- `timestamp`: When action occurred

### Admin Notifications
Stored in `AdminNotification`:
- `notification_type`: 'user_action_block'
- `title`: "User X Blocked IP"
- `message`: "X blocked IP Y via email alert (Risk Score: Z)"
- `related_user_id`: Which user took the action

---

## 🧪 Testing Procedures

### Test 1: Email-Based Block
1. Login as regular user
2. Wait for threat email or trigger notification
3. Click "Block IP" button in email
4. Verify success page displays
5. Navigate to dashboard "Blocked IPs" tab
6. Confirm IP appears in list with correct details
7. Check database for BlockedThreat record
8. Check console for [EMAIL-BLOCK] logs

### Test 2: Token Validation
1. Generate test token manually
2. Test expired token: modify expires_at to past time
3. Test already-used token: set is_used=True
4. Test invalid token: use non-existent token
5. Verify appropriate error messages displayed

### Test 3: Duplicate Prevention
1. Block same IP twice via email
2. Second attempt should show "already blocked" message
3. Unblock the IP
4. Confirm ability to re-block
5. Verify no duplicate database entries created

### Test 4: Admin Notifications
1. Block IP as user
2. Login as admin
3. Check Admin Dashboard for notification
4. Verify notification contains correct details
5. Check database AdminNotification record

### Test 5: Unblock Functionality
1. Navigate to "Blocked IPs" tab as user
2. Click unblock button
3. Confirm in dialog
4. Verify IP status changes to "⚫ Inactive"
5. Confirm action logged in ThreatActionLog

---

## 🔧 Troubleshooting

### Email Not Received
**Issue**: User doesn't receive threat notification email  
**Solutions**:
1. Check ThreatSubscription.is_active = True
2. Verify user's risk score threshold (default ≥75)
3. Check if IP was recently emailed (24-hour deduplication)
4. Verify MAIL_SERVER config in environment
5. Check backend logs for [NOTIFY] messages

### Token Expired Error
**Issue**: User clicks link after token expires  
**Solutions**:
1. Token valid for 24 hours from creation
2. User should click link immediately after receiving email
3. If expired, user can request new threat email
4. No way to extend existing token (security design)

### Invalid IP Format
**Issue**: Error "Invalid IP address format"  
**Solutions**:
1. System extracts IP from multiple fields
2. If extraction fails, block fails
3. Check threat data contains valid ip/ip_address/indicator
4. IP must be valid IPv4 or IPv6 format
5. localhost and private ranges allowed

### Already Blocked Error
**Issue**: "IP was already blocked by you" message  
**Solutions**:
1. User already blocked this IP previously
2. Navigate to "Blocked IPs" tab
3. Click "Unblock IP" if no longer needed
4. Then re-block using new email link if desired

### Admin Notification Missing
**Issue**: Admin doesn't see user action notification  
**Solutions**:
1. Refresh Admin Dashboard
2. Check AdminNotification table in database
3. Verify admin user exists with role='admin'
4. Check backend logs for [EMAIL-BLOCK] messages
5. Verify database commit didn't fail

---

## 🎓 Advanced Topics

### Scaling Considerations
- **Token Storage**: BlockToken table grows with email sends (~100/day)
- **Cleanup**: Consider archiving expired tokens after 30 days
- **Performance**: Indexed queries on token, user_id, ip_address
- **Concurrency**: Database transactions prevent race conditions

### Security Hardening
- **Token Entropy**: 32-byte tokens (256 bits) provide >256 bits of entropy
- **Timing Attacks**: All validation checks take similar time
- **Rate Limiting**: Consider adding rate limits on block endpoint
- **CSRF Protection**: Frontend uses Same-Origin for email links

### Compliance
- **GDPR**: Delete user block history when account deleted
- **Audit Trail**: All actions logged indefinitely
- **Data Retention**: Consider retention policy for blocked IPs
- **User Consent**: Assumes user consented to threat emails

---

## 📝 Summary

The Email-Based IP Blocking system provides:
- ✅ Secure, one-time-use tokens
- ✅ No authentication required for email links
- ✅ Full audit trail and logging
- ✅ Admin notifications of user actions
- ✅ Real-time dashboard updates
- ✅ Unblock capability
- ✅ Duplicate prevention
- ✅ Professional email templates
- ✅ Error handling and validation
- ✅ Production-ready implementation

**Status**: Ready for immediate deployment and user testing.
