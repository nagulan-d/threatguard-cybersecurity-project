# 🔄 CTI Auto-Defense System - Complete Workflow Guide

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [User Workflows](#user-workflows)
3. [Threat Processing Workflow](#threat-processing-workflow)
4. [Auto-Blocking Workflow](#auto-blocking-workflow)
5. [Email Notification Workflow](#email-notification-workflow)
6. [Admin Workflows](#admin-workflows)
7. [Data Flow Diagrams](#data-flow-diagrams)
8. [Integration Workflows](#integration-workflows)

---

## 🎯 System Overview

### High-Level System Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTI Auto-Defense System                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │   1. THREAT INTELLIGENCE COLLECTION      │
        │   (AlienVault OTX API - Every 120s)     │
        └─────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │   2. AI ANALYSIS & ENRICHMENT           │
        │   (Google Gemini - Summarize & Score)   │
        └─────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │   3. CATEGORIZATION & STORAGE           │
        │   (Database - Deduplicate & Store)      │
        └─────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │   4. RISK ASSESSMENT                    │
        │   (Score >= 75 = High Risk)             │
        └─────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
    ┌──────────────────────┐    ┌──────────────────────┐
    │  5A. EMAIL ALERTS     │    │  5B. AUTO-BLOCKING   │
    │  (Subscribed Users)   │    │  (Windows Firewall)  │
    └──────────────────────┘    └──────────────────────┘
                │                           │
                ▼                           ▼
    ┌──────────────────────┐    ┌──────────────────────┐
    │  6A. User Action      │    │  6B. Firewall Rules  │
    │  (Click Block IP)     │    │  (IN + OUT Rules)    │
    └──────────────────────┘    └──────────────────────┘
                │                           │
                └─────────────┬─────────────┘
                              ▼
                ┌──────────────────────────┐
                │   7. AUDIT LOGGING        │
                │   (ThreatActionLog)       │
                └──────────────────────────┘
```

---

## 👤 User Workflows

### 1. User Registration & Onboarding

```
START: User visits http://localhost:3000
    │
    ▼
┌─────────────────────────┐
│  1. Click "Register"    │
└─────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Fill Registration Form:             │
│     - Username                          │
│     - Email                             │
│     - Phone                             │
│     - Password (min 8 chars)            │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Frontend validates input:           │
│     ✓ Email format valid                │
│     ✓ Password meets requirements       │
│     ✓ All fields filled                 │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. POST /api/register                  │
│     Request: {username, email, phone,   │
│              password}                  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Backend Processing:                 │
│     - Check if username exists          │
│     - Check if email exists             │
│     - Hash password (PBKDF2-SHA256)     │
│     - Create User record                │
│     - Save to database                  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Response:                           │
│     Status: 201 Created                 │
│     Body: {"message": "User registered  │
│            successfully",               │
│            "user_id": 42}               │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Frontend redirects to Login page    │
└─────────────────────────────────────────┘
    │
    ▼
END: User can now login
```

**Error Handling:**
- Username exists → Show error: "Username already taken"
- Email exists → Show error: "Email already registered"
- Weak password → Show error: "Password must be at least 8 characters"

---

### 2. User Login & Authentication

```
START: User on Login page
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Enter credentials:                  │
│     - Username: "admin"                 │
│     - Password: "admin123"              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Click "Login"                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. POST /api/login                     │
│     Request: {username, password}       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Backend Authentication:             │
│     - Find user by username             │
│     - Verify password hash              │
│     - check_password_hash(stored, input)│
└─────────────────────────────────────────┘
    │
    ├─── Invalid credentials ──────────────> Error: "Invalid username/password"
    │
    ▼ Valid credentials
┌─────────────────────────────────────────┐
│  5. Generate JWT Token:                 │
│     payload = {                         │
│         'user_id': 42,                  │
│         'username': 'admin',            │
│         'role': 'admin',                │
│         'exp': now + 24 hours           │
│     }                                   │
│     token = jwt.encode(payload, SECRET) │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Response:                           │
│     Status: 200 OK                      │
│     Body: {                             │
│         "token": "eyJhbGc...",          │
│         "user": {                       │
│             "id": 42,                   │
│             "username": "admin",        │
│             "role": "admin",            │
│             "subscription": "premium"   │
│         }                               │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Frontend stores token:              │
│     localStorage.setItem('token', ...)  │
│     localStorage.setItem('user', ...)   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Redirect to Dashboard               │
│     URL: /dashboard                     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  9. Dashboard loads:                    │
│     - Fetch threats                     │
│     - Connect WebSocket                 │
│     - Display recent activity           │
└─────────────────────────────────────────┘
    │
    ▼
END: User authenticated and in dashboard
```

**Token Usage:**
All subsequent API requests include:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### 3. Viewing Threats Workflow

```
START: User on Dashboard
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Dashboard component mounts          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. GET /api/threats                    │
│     Headers: Authorization: Bearer ...  │
│     Query: ?limit=50&category=all       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Backend validates JWT token         │
│     - Decode token                      │
│     - Check expiration                  │
│     - Extract user_id                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Query database:                     │
│     SELECT * FROM threat_indicator      │
│     ORDER BY last_seen DESC             │
│     LIMIT 50                            │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Response:                           │
│     Status: 200 OK                      │
│     Body: {                             │
│         "threats": [                    │
│             {                           │
│                 "id": 1234,             │
│                 "indicator": "1.2.3.4", │
│                 "type": "IPv4",         │
│                 "severity": "High",     │
│                 "score": 87.5,          │
│                 "category": "Malware",  │
│                 "summary": "..."        │
│             },                          │
│             ...                         │
│         ],                              │
│         "total": 50                     │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Frontend renders threats:           │
│     - Display in table/cards            │
│     - Color-code by severity:           │
│       • High = Red                      │
│       • Medium = Orange                 │
│       • Low = Yellow                    │
│     - Show "Block IP" button for IPs    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. User can:                           │
│     ✓ Filter by category                │
│     ✓ Filter by severity                │
│     ✓ Search by indicator               │
│     ✓ Sort by score/date                │
│     ✓ Click threat for details          │
│     ✓ Block IP addresses                │
└─────────────────────────────────────────┘
    │
    ▼
END: Threats displayed
```

**Filter Workflow:**
```
User selects "Category: Phishing"
    ↓
GET /api/threats?category=Phishing
    ↓
Backend filters: WHERE category = 'Phishing'
    ↓
Frontend updates display
```

---

### 4. Blocking IP Workflow (Manual)

```
START: User sees high-risk IP threat
    │
    ▼
┌─────────────────────────────────────────┐
│  1. User clicks "Block IP" button       │
│     IP: 192.168.1.100                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Confirmation dialog appears:        │
│     "Block IP 192.168.1.100?"           │
│     [Cancel] [Confirm]                  │
└─────────────────────────────────────────┘
    │
    ▼ User confirms
┌─────────────────────────────────────────┐
│  3. POST /api/block-ip                  │
│     Headers: Authorization: Bearer ...  │
│     Body: {                             │
│         "ip_address": "192.168.1.100",  │
│         "reason": "Manual block",       │
│         "threat_data": {                │
│             "threat_type": "Malware",   │
│             "risk_score": 87.5,         │
│             "category": "High"          │
│         }                               │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Backend validates:                  │
│     ✓ User authenticated                │
│     ✓ IP format valid (IPv4/IPv6)       │
│     ✓ IP not already blocked            │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Create Windows Firewall Rules:      │
│                                         │
│  A. INBOUND RULE:                       │
│     netsh advfirewall firewall add rule │
│     name="ThreatGuard_Block_IN_192_168_1_100" │
│     dir=in action=block                 │
│     remoteip=192.168.1.100              │
│                                         │
│  B. OUTBOUND RULE:                      │
│     netsh advfirewall firewall add rule │
│     name="ThreatGuard_Block_OUT_192_168_1_100"│
│     dir=out action=block                │
│     remoteip=192.168.1.100              │
└─────────────────────────────────────────┘
    │
    ├─── Firewall error ──────────────────> Error: "Admin privileges required"
    │
    ▼ Success
┌─────────────────────────────────────────┐
│  6. Create database record:             │
│     INSERT INTO blocked_threat (        │
│         user_id,                        │
│         ip_address,                     │
│         threat_type,                    │
│         risk_score,                     │
│         blocked_by = 'user',            │
│         is_active = TRUE,               │
│         blocked_at = NOW()              │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Create audit log:                   │
│     INSERT INTO threat_action_log (     │
│         user_id,                        │
│         action = 'manual_block',        │
│         ip_address,                     │
│         details = JSON({...}),          │
│         timestamp = NOW()               │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Response:                           │
│     Status: 200 OK                      │
│     Body: {                             │
│         "message": "IP blocked",        │
│         "firewall_rules": [             │
│             "ThreatGuard_Block_IN_...", │
│             "ThreatGuard_Block_OUT_..." │
│         ],                              │
│         "blocked_id": 567               │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  9. Frontend updates:                   │
│     - Show success message              │
│     - Update blocked IPs list           │
│     - Disable "Block IP" button         │
│     - Show "Unblock" option             │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  10. WebSocket broadcast:               │
│      Event: "ip_blocked"                │
│      Payload: {ip, user, timestamp}     │
│      → All connected clients update UI  │
└─────────────────────────────────────────┘
    │
    ▼
END: IP blocked successfully
```

**Verification:**
```powershell
# User can verify block
netsh advfirewall firewall show rule name="ThreatGuard_Block_IN_192_168_1_100"

# Test connectivity (should fail)
ping 192.168.1.100
Test-NetConnection 192.168.1.100 -Port 443
```

---

### 5. Unblocking IP Workflow

```
START: User on Blocked IPs page
    │
    ▼
┌─────────────────────────────────────────┐
│  1. User clicks "Unblock" button        │
│     IP: 192.168.1.100                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Confirmation dialog:                │
│     "Unblock IP 192.168.1.100?"         │
│     "This will allow traffic from/to    │
│      this IP address."                  │
│     [Cancel] [Confirm]                  │
└─────────────────────────────────────────┘
    │
    ▼ User confirms
┌─────────────────────────────────────────┐
│  3. DELETE /api/unblock-ip/192.168.1.100│
│     Headers: Authorization: Bearer ...  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Backend validates:                  │
│     ✓ User authenticated                │
│     ✓ IP is currently blocked           │
│     ✓ User has permission (owner/admin) │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Delete Windows Firewall Rules:      │
│                                         │
│  A. Delete INBOUND:                     │
│     netsh advfirewall firewall delete   │
│     rule name="ThreatGuard_Block_IN_192_168_1_100" │
│                                         │
│  B. Delete OUTBOUND:                    │
│     netsh advfirewall firewall delete   │
│     rule name="ThreatGuard_Block_OUT_192_168_1_100"│
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Update database record:             │
│     UPDATE blocked_threat SET           │
│         is_active = FALSE,              │
│         unblocked_at = NOW(),           │
│         unblocked_by_user_id = user_id  │
│     WHERE ip_address = '192.168.1.100'  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Create audit log:                   │
│     INSERT INTO threat_action_log (     │
│         user_id,                        │
│         action = 'unblock',             │
│         ip_address,                     │
│         timestamp = NOW()               │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Response:                           │
│     Status: 200 OK                      │
│     Body: {                             │
│         "message": "IP unblocked",      │
│         "ip_address": "192.168.1.100"   │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  9. Frontend updates:                   │
│     - Show success message              │
│     - Remove from blocked list          │
│     - Re-enable "Block IP" button       │
└─────────────────────────────────────────┘
    │
    ▼
END: IP unblocked successfully
```

---

### 6. Email Subscription Workflow

```
START: User wants to receive threat alerts
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Navigate to Settings/Notifications  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Toggle "Email Notifications" ON     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Configure preferences:              │
│     - Email: john@example.com           │
│     - Min Risk Score: 75 (High only)    │
│     - Categories: All / Specific        │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Click "Save Preferences"            │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. POST /api/subscribe-notifications   │
│     Headers: Authorization: Bearer ...  │
│     Body: {                             │
│         "email": "john@example.com",    │
│         "min_risk_score": 75            │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Backend creates subscription:       │
│     INSERT INTO threat_subscription (   │
│         user_id,                        │
│         email,                          │
│         is_active = TRUE,               │
│         min_risk_score = 75,            │
│         subscribed_at = NOW()           │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Send confirmation email:            │
│     Subject: "Threat Alerts Activated"  │
│     Body: "You will receive alerts for  │
│            threats with score >= 75"    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Response:                           │
│     Status: 200 OK                      │
│     Body: {                             │
│         "message": "Subscribed",        │
│         "subscription_id": 123          │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
END: User subscribed to email alerts
```

**Unsubscribe Workflow:**
```
User clicks "Unsubscribe" in email
    ↓
GET /api/unsubscribe?token=xxx
    ↓
Backend: UPDATE threat_subscription SET is_active = FALSE
    ↓
Display: "You've been unsubscribed"
```

---

## 🤖 Threat Processing Workflow

### 1. Complete Threat Lifecycle

```
┌──────────────────────────────────────────────────────────────┐
│                    THREAT LIFECYCLE                           │
└──────────────────────────────────────────────────────────────┘

START: Threat Fetcher Service (runs every 120 seconds)
    │
    ▼
┌─────────────────────────────────────────┐
│  STAGE 1: COLLECTION                    │
│  ─────────────────────────────────────  │
│  1. GET AlienVault OTX API              │
│     URL: /api/v1/indicators/export      │
│     Params:                             │
│       - types: FileHash-SHA256,IPv4,    │
│                domain,URL               │
│       - modified_since: last_fetch_time │
│       - limit: 100                      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Receive raw indicators:             │
│     [                                   │
│         {                               │
│             "indicator": "1.2.3.4",     │
│             "type": "IPv4",             │
│             "pulse_info": {...},        │
│             "created": "2026-02-21...", │
│             ...                         │
│         },                              │
│         ...                             │
│     ]                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  STAGE 2: ENRICHMENT                    │
│  ─────────────────────────────────────  │
│  3. For each indicator:                 │
│                                         │
│  A. AI Summarization (Gemini):         │
│     Input: Raw indicator + pulse data   │
│     Prompt: "Summarize this threat in   │
│              50 words for CTI analyst"  │
│     Output: "Russian APT group C2       │
│              server used in financial   │
│              sector attacks..."         │
│                                         │
│  B. Risk Scoring:                       │
│     Factors:                            │
│       • Pulse confidence (0-100)        │
│       • Reference count                 │
│       • Indicator age (recency)         │
│       • Tag reputation                  │
│       • Random variance (distribution)  │
│     Formula:                            │
│       score = base(20-95) +             │
│               (confidence/100)*10 +     │
│               min(refs, 5) +            │
│               recency_bonus(0-30)       │
│     Output: 87.5                        │
│                                         │
│  C. Severity Classification:            │
│     if score >= 75: "High"              │
│     elif score >= 50: "Medium"          │
│     else: "Low"                         │
│                                         │
│  D. Categorization:                     │
│     Tags: ['malware', 'apt', 'c2']      │
│     → Match keywords →                  │
│     Category: "Malware"                 │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  STAGE 3: DEDUPLICATION                 │
│  ─────────────────────────────────────  │
│  4. Check if threat exists:             │
│     Query:                              │
│       SELECT * FROM threat_indicator    │
│       WHERE indicator_value = '1.2.3.4' │
│       OR otx_id = 'abc123'              │
│                                         │
│  If EXISTS:                             │
│    → UPDATE last_seen = NOW()           │
│    → Skip further processing            │
│                                         │
│  If NEW:                                │
│    → Continue to next stage             │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  STAGE 4: STORAGE                       │
│  ─────────────────────────────────────  │
│  5. Store enriched threat:              │
│     INSERT INTO threat_indicator (      │
│         indicator_value = '1.2.3.4',    │
│         indicator_type = 'IPv4',        │
│         category = 'Malware',           │
│         severity = 'High',              │
│         score = 87.5,                   │
│         summary = '...',                │
│         pulse_count = 3,                │
│         first_seen = NOW(),             │
│         last_seen = NOW(),              │
│         otx_id = 'abc123'               │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  STAGE 5: RISK EVALUATION               │
│  ─────────────────────────────────────  │
│  6. Check if high-risk:                 │
│     if score >= 75:                     │
│         → Trigger email notifications   │
│         → Trigger auto-blocking         │
└─────────────────────────────────────────┘
    │
    ├────────────────────────┬────────────────────────┐
    ▼                        ▼                        ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Email Module │  │ Auto-Block Module│  │ Dashboard Update │
│ (See below)  │  │ (See below)      │  │ (WebSocket)      │
└──────────────┘  └──────────────────┘  └──────────────────┘
    │
    ▼
END: Threat processed
```

---

### 2. Threat Fetcher Service Details

```
┌─────────────────────────────────────────────────────────┐
│         Threat Fetcher Background Service                │
│         (backend/fetch_realtime_threats.py)             │
└─────────────────────────────────────────────────────────┘

INITIALIZATION:
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Load configuration:                 │
│     - API_KEY (AlienVault OTX)          │
│     - GEMINI_API_KEY                    │
│     - THREATS_POLL_INTERVAL = 120s      │
│     - THREATS_LIMIT = 30                │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Initialize AI clients:              │
│     - init_summarizer(GEMINI_API_KEY)   │
│     - init_scorer(GEMINI_API_KEY)       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Start infinite loop:                │
│     while True:                         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Fetch threats from OTX:             │
│                                         │
│  A. Build request:                      │
│     GET https://otx.alienvault.com/     │
│         api/v1/indicators/export        │
│     Headers:                            │
│       X-OTX-API-KEY: {API_KEY}          │
│     Params:                             │
│       types: FileHash-SHA256,IPv4,      │
│              domain,URL                 │
│       modified_since: {last_timestamp}  │
│       limit: 30                         │
│                                         │
│  B. Send request:                       │
│     response = requests.get(url, ...)   │
│                                         │
│  C. Handle errors:                      │
│     - 429 Rate Limited:                 │
│       → Sleep 60s, retry                │
│     - 401 Unauthorized:                 │
│       → Log error, check API key        │
│     - Timeout:                          │
│       → Retry with exponential backoff  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Parse response:                     │
│     if response.ok:                     │
│         indicators = response.json()    │
│         ['results']                     │
│     else:                               │
│         log error and skip              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Process each indicator:             │
│     for indicator in indicators:        │
│         1. Extract fields               │
│         2. Summarize with Gemini        │
│         3. Score threat                 │
│         4. Categorize                   │
│         5. Check for duplicate          │
│         6. Save to database             │
│         7. Trigger actions if high-risk │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Update last fetch timestamp:        │
│     last_timestamp = NOW()              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Sleep until next cycle:             │
│     time.sleep(THREATS_POLL_INTERVAL)   │
│     # 120 seconds                       │
└─────────────────────────────────────────┘
    │
    └──────> Return to step 4 (loop)
```

**Error Recovery:**
- API failure: Log error, continue to sleep, retry next cycle
- Database error: Rollback transaction, log error, continue
- AI API failure: Use fallback (default summary/score)

---

## 🚫 Auto-Blocking Workflow

### Complete Auto-Blocking Process

```
┌──────────────────────────────────────────────────────────┐
│               AUTOMATED IP BLOCKING WORKFLOW              │
│           (Triggered for High-Risk IP Threats)           │
└──────────────────────────────────────────────────────────┘

TRIGGER: New IP threat with score >= 75
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Check auto-block configuration:     │
│     if AUTO_BLOCK_ENABLED != true:      │
│         → ABORT (skip auto-blocking)    │
│     else:                               │
│         → PROCEED                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Validate indicator is IP:           │
│     indicator_type in ('IPv4', 'IP'):   │
│         → PROCEED                       │
│     else:                               │
│         → ABORT (can't block non-IPs)   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Extract IP address:                 │
│     indicator = "192.168.1.100/24"      │
│                                         │
│  A. Remove CIDR notation:               │
│     ip = indicator.split('/')[0]        │
│     # Result: "192.168.1.100"           │
│                                         │
│  B. Validate IP format:                 │
│     if not is_valid_ip(ip):             │
│         → ABORT                         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Check if already blocked:           │
│     Query:                              │
│       SELECT * FROM blocked_threat      │
│       WHERE ip_address = ip             │
│       AND is_active = TRUE              │
│                                         │
│     If EXISTS:                          │
│         → ABORT (already blocked)       │
│     else:                               │
│         → PROCEED                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Call IP Blocker module:             │
│     from ip_blocker import ip_blocker   │
│     result = ip_blocker.block_ip(ip)    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. IP Blocker creates firewall rules:  │
│                                         │
│  A. Format rule names:                  │
│     ip_safe = ip.replace('.', '_')      │
│     rule_in = f"ThreatGuard_Block_IN_{ip_safe}"  │
│     rule_out = f"ThreatGuard_Block_OUT_{ip_safe}"│
│                                         │
│  B. Create INBOUND rule:                │
│     cmd = [                             │
│         'netsh', 'advfirewall',         │
│         'firewall', 'add', 'rule',      │
│         f'name={rule_in}',              │
│         'dir=in',                       │
│         'action=block',                 │
│         f'remoteip={ip}',               │
│         'enable=yes'                    │
│     ]                                   │
│     subprocess.run(cmd, check=True)     │
│                                         │
│  C. Create OUTBOUND rule:               │
│     cmd = [                             │
│         'netsh', 'advfirewall',         │
│         'firewall', 'add', 'rule',      │
│         f'name={rule_out}',             │
│         'dir=out',                      │
│         'action=block',                 │
│         f'remoteip={ip}',               │
│         'enable=yes'                    │
│     ]                                   │
│     subprocess.run(cmd, check=True)     │
│                                         │
│  D. Verify rules created:               │
│     cmd = ['netsh', 'advfirewall',      │
│            'firewall', 'show', 'rule',  │
│            f'name={rule_in}']           │
│     output = subprocess.run(cmd)        │
│     if "No rules match" in output:      │
│         → ERROR: Rule creation failed   │
└─────────────────────────────────────────┘
    │
    ├─── Admin privileges missing ─────────> ERROR: Log failure, skip
    │                                        (Backend needs to run as Admin)
    ▼
┌─────────────────────────────────────────┐
│  7. Save to database:                   │
│     INSERT INTO blocked_threat (        │
│         user_id = 1,  # Admin user      │
│         ip_address = '192.168.1.100',   │
│         threat_type = 'Malware',        │
│         risk_category = 'High',         │
│         risk_score = 87.5,              │
│         summary = '...',                │
│         blocked_by = 'admin',           │
│         blocked_by_user_id = 1,         │
│         is_active = TRUE,               │
│         blocked_at = NOW(),             │
│         reason = 'Automated block -     │
│                   High-risk threat'     │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Create audit log:                   │
│     INSERT INTO threat_action_log (     │
│         user_id = 1,                    │
│         action = 'auto_block',          │
│         ip_address = '192.168.1.100',   │
│         details = JSON({                │
│             'threat_type': 'Malware',   │
│             'risk_score': 87.5,         │
│             'category': 'Malware',      │
│             'firewall_rules': [         │
│                 'ThreatGuard_Block_IN_...',│
│                 'ThreatGuard_Block_OUT_...'│
│             ]                           │
│         }),                             │
│         timestamp = NOW(),              │
│         success = TRUE                  │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  9. Broadcast WebSocket event:          │
│     ws.broadcast({                      │
│         'event': 'ip_auto_blocked',     │
│         'data': {                       │
│             'ip': '192.168.1.100',      │
│             'score': 87.5,              │
│             'category': 'Malware',      │
│             'timestamp': '2026-02-21...'│
│         }                               │
│     })                                  │
│     → All connected dashboards update   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  10. Rate limit check:                  │
│      blocks_this_cycle += 1             │
│      if blocks_this_cycle >=            │
│         AUTO_BLOCK_MAX_PER_CYCLE:       │
│          → Stop blocking for this cycle │
│      else:                              │
│          → Continue processing          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  11. Delay before next block:           │
│      time.sleep(AUTO_BLOCK_DELAY)       │
│      # Default: 30 seconds              │
└─────────────────────────────────────────┘
    │
    ▼
END: IP auto-blocked successfully

Console Output:
─────────────────────────────────────────
✅ Auto-blocked IP: 192.168.1.100
   Risk Score: 87.5
   Category: Malware
   Firewall Rules Created:
   - ThreatGuard_Block_IN_192_168_1_100
   - ThreatGuard_Block_OUT_192_168_1_100
```

**Configuration Parameters:**
```python
AUTO_BLOCK_ENABLED = true          # Master switch
AUTO_BLOCK_THRESHOLD = 75          # Min score for auto-block
AUTO_BLOCK_DELAY = 30              # Seconds between blocks
AUTO_BLOCK_MAX_PER_CYCLE = 5       # Max blocks per 2-minute cycle
```

---

## 📧 Email Notification Workflow

### Complete Email Notification Process

```
┌──────────────────────────────────────────────────────────┐
│            EMAIL NOTIFICATION WORKFLOW                    │
│         (Triggered for High-Risk Threats)                │
└──────────────────────────────────────────────────────────┘

TRIGGER: High-risk threat (score >= NOTIFY_THRESHOLD)
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Check notification threshold:       │
│     if threat_score >= NOTIFY_THRESHOLD:│
│         # Default: 80                   │
│         → PROCEED                       │
│     else:                               │
│         → ABORT                         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Query subscribed users:             │
│     SELECT u.*, ts.*                    │
│     FROM user u                         │
│     JOIN threat_subscription ts         │
│       ON u.id = ts.user_id              │
│     WHERE ts.is_active = TRUE           │
│       AND ts.min_risk_score <= {score}  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. For each subscribed user:           │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Check rate limiting:                │
│     last_notification = user.           │
│         last_notification_sent          │
│     if NOW() - last_notification < 5min:│
│         → SKIP (too soon)              │
│     else:                               │
│         → PROCEED                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Generate block token:               │
│     from email_service import           │
│         generate_block_token            │
│                                         │
│     token = secrets.token_urlsafe(32)   │
│     # Result: "Xk7n9Lm..."             │
│                                         │
│     Store token mapping:                │
│     {                                   │
│         'token': token,                 │
│         'user_id': user.id,             │
│         'ip_address': threat.ip,        │
│         'threat_data': {...},           │
│         'expires_at': NOW() + 24h,      │
│         'created_at': NOW()             │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Build email content:                │
│     from email_service import           │
│         get_threat_email_template       │
│                                         │
│  A. Prepare data:                       │
│     threat_data = {                     │
│         'indicator': '192.168.1.100',   │
│         'threat_type': 'Malware',       │
│         'risk_score': 87.5,             │
│         'category': 'Malware',          │
│         'severity': 'High',             │
│         'summary': '...',               │
│         'timestamp': '2026-02-21...'    │
│     }                                   │
│                                         │
│  B. Generate action URLs:               │
│     block_url = f"http://localhost:5000/│
│                   api/block-threat?     │
│                   token={token}"        │
│     unsubscribe_url = f"http://localhost│
│                   :5000/api/unsubscribe?│
│                   user_id={user.id}"    │
│                                         │
│  C. Render HTML template:               │
│     html = get_threat_email_template(   │
│         user_name = user.username,      │
│         threat_data = threat_data,      │
│         block_url = block_url,          │
│         unsubscribe_url = unsubscribe_url,│
│         is_subscribed = (user.subscription│
│                          == 'premium')   │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Email Template Structure:           │
│                                         │
│  ┌────────────────────────────────┐    │
│  │  🛡️ THREAT ALERT               │    │
│  │  ────────────────────────────   │    │
│  │  High-Risk Threat Detected      │    │
│  │                                 │    │
│  │  📍 IP: 192.168.1.100          │    │
│  │  ⚠️  Risk: 87.5 (High)          │    │
│  │  🎯 Type: Malware C2 Server     │    │
│  │  📅 Detected: 2026-02-21 10:30 │    │
│  │                                 │    │
│  │  Summary:                       │    │
│  │  Russian APT group command...   │    │
│  │                                 │    │
│  │  ┌───────────────────────┐      │    │
│  │  │ [🚫 BLOCK THIS IP] │      │    │
│  │  └───────────────────────┘      │    │
│  │                                 │    │
│  │  Prevention Hints:              │    │
│  │  • Block IP at firewall         │    │
│  │  • Check access logs            │    │
│  │  • Monitor related traffic      │    │
│  │                                 │    │
│  │  ────────────────────────────   │    │
│  │  [View Dashboard] [Unsubscribe] │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Send email via SMTP:                │
│     from flask_mail import Message      │
│                                         │
│  A. Create message:                     │
│     msg = Message(                      │
│         subject = f"🚨 High-Risk Threat:│
│                     {threat_type}",     │
│         sender = MAIL_USERNAME,         │
│         recipients = [user.email],      │
│         html = html                     │
│     )                                   │
│                                         │
│  B. Connect to Gmail SMTP:              │
│     Server: smtp.gmail.com:587          │
│     TLS: Enabled                        │
│     Auth: MAIL_USERNAME, MAIL_PASSWORD  │
│                                         │
│  C. Send:                               │
│     mail.send(msg)                      │
│                                         │
│  D. Handle errors:                      │
│     - SMTPAuthenticationError:          │
│       → Log error, check credentials    │
│     - SMTPConnectError:                 │
│       → Retry after 10s                 │
│     - Timeout:                          │
│       → Log failure, create in-app      │
│         notification as fallback        │
└─────────────────────────────────────────┘
    │
    ├─── Email sent successfully ───────────┐
    │                                       │
    ▼                                       ▼
┌─────────────────────────────────┐   ┌──────────────────────┐
│  9A. Email Success:             │   │  9B. Email Failed:   │
│                                 │   │                      │
│  - Update user record:          │   │  - Create fallback   │
│    UPDATE threat_subscription   │   │    notification:     │
│    SET last_notification_sent   │   │    INSERT INTO       │
│        = NOW()                  │   │    notification (    │
│    WHERE user_id = ...          │   │      user_id,        │
│                                 │   │      subject,        │
│  - Create notification record:  │   │      body,           │
│    INSERT INTO notification (   │   │      sent_via_email  │
│      user_id,                   │   │        = FALSE       │
│      subject,                   │   │    )                 │
│      body,                      │   │                      │
│      sent_via_email = TRUE      │   │  - User can view in  │
│    )                            │   │    dashboard         │
└─────────────────────────────────┘   └──────────────────────┘
    │                                       │
    └───────────────┬───────────────────────┘
                    ▼
┌─────────────────────────────────────────┐
│  10. Create audit log:                  │
│      INSERT INTO threat_action_log (    │
│          user_id,                       │
│          action = 'email_sent',         │
│          ip_address,                    │
│          details = JSON({               │
│              'email': user.email,       │
│              'threat_score': 87.5,      │
│              'delivery_status': 'sent'  │
│          }),                            │
│          timestamp = NOW(),             │
│          success = TRUE                 │
│      )                                  │
└─────────────────────────────────────────┘
    │
    ▼
END: Email notification sent

Console Output:
─────────────────────────────────────────
📧 Sent threat notification:
   To: user@example.com
   Subject: 🚨 High-Risk Threat: Malware
   IP: 192.168.1.100
   Score: 87.5
   Status: ✅ Delivered
```

### One-Click Block Workflow (From Email)

```
User receives email
    │
    ▼
User clicks "BLOCK THIS IP" button
    │
    ▼
Browser opens: http://localhost:5000/api/block-threat?token=Xk7n9Lm...
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Backend validates token:            │
│     - Decode token                      │
│     - Check if exists in token store    │
│     - Check if expired (> 24 hours)     │
│     - Check if already used             │
└─────────────────────────────────────────┘
    │
    ├─── Invalid/expired ──────> Display: "Token invalid or expired"
    │
    ▼ Valid
┌─────────────────────────────────────────┐
│  2. Extract data from token:            │
│     user_id = token_data['user_id']     │
│     ip = token_data['ip_address']       │
│     threat_data = token_data['threat']  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Block IP (same as manual workflow): │
│     - Create firewall rules             │
│     - Update database                   │
│     - Create audit log                  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Mark token as used:                 │
│     DELETE FROM token_store             │
│     WHERE token = 'Xk7n9Lm...'          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Display confirmation page:          │
│     "✅ IP 192.168.1.100 blocked"       │
│     "View your dashboard"               │
└─────────────────────────────────────────┘
    │
    ▼
END: IP blocked via email
```

---

## 👑 Admin Workflows

### 1. Global IP Blocking (Admin)

```
START: Admin user logged in
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Navigate to Admin Panel             │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Enter IP to block:                  │
│     - IP Address: 10.20.30.40           │
│     - Reason: "Known botnet node"       │
│     - Category: "Malware"               │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Click "Block for All Users"         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. POST /api/admin/block-ip            │
│     Headers:                            │
│       Authorization: Bearer {admin_token}│
│     Body: {                             │
│         "ip_address": "10.20.30.40",    │
│         "reason": "Known botnet node",  │
│         "category": "Malware",          │
│         "block_for_all": true           │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Backend validates admin role:       │
│     if user.role != 'admin':            │
│         → ERROR: "Unauthorized"         │
│     else:                               │
│         → PROCEED                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  6. Create global block:                │
│     - Create firewall rules             │
│     - Create DB record with             │
│       blocked_by='admin'                │
│     - Mark as global (affects all users)│
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  7. Notify all users:                   │
│     For each active user:               │
│         - Send email notification       │
│         - Create in-app notification    │
│         Subject: "Admin blocked IP:     │
│                   10.20.30.40"          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  8. Broadcast WebSocket:                │
│     Event: "admin_block"                │
│     → All dashboards show banner        │
└─────────────────────────────────────────┘
    │
    ▼
END: IP blocked globally
```

---

### 2. User Management Workflow

```
START: Admin in Admin Panel
    │
    ▼
┌─────────────────────────────────────────┐
│  1. View Users List                     │
│     GET /api/admin/users                │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Display user table:                 │
│     ┌──────────────────────────────┐    │
│     │ ID │ Username │ Role │ Sub   │    │
│     ├────┼──────────┼──────┼───────┤    │
│     │ 1  │ admin    │ admin│premium│    │
│     │ 2  │ john     │ user │ free  │    │
│     │ 3  │ jane     │ user │premium│    │
│     └──────────────────────────────┘    │
└─────────────────────────────────────────┘
    │
    ▼
Admin selects user action:
    │
    ├─── A. Upgrade to Premium ───────────────┐
    │                                          │
    ├─── B. Promote to Admin ─────────────────┤
    │                                          │
    └─── C. Deactivate User ──────────────────┤
                                               │
                                               ▼
                          ┌────────────────────────────────┐
                          │  PATCH /api/admin/users/{id}   │
                          │  Body: {"subscription": "premium"}│
                          │     OR {"role": "admin"}       │
                          │     OR {"is_active": false}    │
                          └────────────────────────────────┘
                                               │
                                               ▼
                          ┌────────────────────────────────┐
                          │  Update database:              │
                          │  UPDATE user SET ...           │
                          │  WHERE id = {user_id}          │
                          └────────────────────────────────┘
                                               │
                                               ▼
                          ┌────────────────────────────────┐
                          │  Send notification to user:    │
                          │  "Your account has been updated"│
                          └────────────────────────────────┘
                                               │
                                               ▼
                                    END: User updated
```

---

### 3. Audit Log Review Workflow

```
START: Admin wants to review activity
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Navigate to Audit Logs              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. GET /api/admin/audit-logs           │
│     Query params:                       │
│       - action: 'block', 'unblock', etc.│
│       - user_id: Filter by user         │
│       - date_from: Start date           │
│       - date_to: End date               │
│       - limit: 100                      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Backend queries:                    │
│     SELECT * FROM threat_action_log     │
│     WHERE action LIKE '%{filter}%'      │
│       AND timestamp BETWEEN             │
│           {date_from} AND {date_to}     │
│     ORDER BY timestamp DESC             │
│     LIMIT 100                           │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Display audit log table:            │
│     ┌─────────────────────────────────────┐│
│     │Time      │User │Action│IP     │Details││
│     ├──────────┼─────┼──────┼───────┼───────┤│
│     │10:30:15 │admin│block │1.2.3.4│High...││
│     │10:25:42 │john │login │-      │Success││
│     │10:20:11 │admin│email │5.6.7.8│Sent...││
│     └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Admin can:                          │
│     - Export to CSV                     │
│     - Filter by user/action/date        │
│     - View full details (JSON)          │
│     - Search by IP address              │
└─────────────────────────────────────────┘
    │
    ▼
END: Audit complete
```

---

## 📊 Data Flow Diagrams

### 1. Real-Time Update Flow

```
┌──────────────────────────────────────────────────────────┐
│              REAL-TIME DATA FLOW (WebSocket)             │
└──────────────────────────────────────────────────────────┘

Backend Event Occurs:
    │
    ├─── New threat detected
    ├─── IP blocked/unblocked
    ├─── User action
    └─── System alert
    │
    ▼
┌─────────────────────────────────────────┐
│  WebSocket Server (Port 8080)           │
│  websocket_server.py                    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Broadcast to all connected clients:    │
│  ws.broadcast({                         │
│      'event': 'threat_update',          │
│      'data': {...}                      │
│  })                                     │
└─────────────────────────────────────────┘
    │
    ▼
    ├──────────────┬──────────────┬──────────────┐
    ▼              ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Client 1 │  │ Client 2 │  │ Client 3 │  │ Client N │
│ (Browser)│  │ (Browser)│  │ (Browser)│  │ (Browser)│
└──────────┘  └──────────┘  └──────────┘  └──────────┘
    │              │              │              │
    ▼              ▼              ▼              ▼
Update Dashboard Components:
    - ThreatsList
    - BlockedIPsTable
    - Statistics counters
    - Notification badges

NO PAGE REFRESH REQUIRED
```

---

### 2. Authentication Flow Diagram

```
┌────────────┐                    ┌────────────┐
│            │                    │            │
│  Browser   │                    │   Backend  │
│            │                    │            │
└────────────┘                    └────────────┘
      │                                  │
      │  POST /api/login                │
      │  {username, password}            │
      │─────────────────────────────────>│
      │                                  │
      │                             Validate
      │                             credentials
      │                                  │
      │  200 OK                          │
      │  {token, user}                   │
      │<─────────────────────────────────│
      │                                  │
Store token in                           │
localStorage                             │
      │                                  │
      │  GET /api/threats                │
      │  Authorization: Bearer {token}   │
      │─────────────────────────────────>│
      │                                  │
      │                             Verify JWT
      │                             Extract user_id
      │                                  │
      │  200 OK                          │
      │  {threats: [...]}                │
      │<─────────────────────────────────│
      │                                  │
      │  POST /api/block-ip              │
      │  Authorization: Bearer {token}   │
      │─────────────────────────────────>│
      │                                  │
      │                             Verify JWT
      │                             Check role
      │                             Process request
      │                                  │
      │  200 OK                          │
      │  {message: "IP blocked"}         │
      │<─────────────────────────────────│
      │                                  │
```

---

## 🔗 Integration Workflows

### 1. AlienVault OTX Integration

```
┌─────────────────────────────────────────────────────────┐
│         ALIENVAULT OTX API INTEGRATION                   │
└─────────────────────────────────────────────────────────┘

Backend Service (Every 120s)
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Prepare API request:                │
│     URL: https://otx.alienvault.com/    │
│          api/v1/indicators/export       │
│     Headers:                            │
│       X-OTX-API-KEY: {YOUR_API_KEY}     │
│     Method: GET                         │
│     Params:                             │
│       types: IPv4,domain,FileHash-SHA256│
│       modified_since: 2026-02-21T10:00  │
│       limit: 30                         │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Send HTTP request                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. OTX responds with JSON:             │
│     {                                   │
│       "results": [                      │
│         {                               │
│           "indicator": "1.2.3.4",       │
│           "type": "IPv4",               │
│           "pulse_info": {               │
│             "pulses": [...]             │
│           },                            │
│           "created": "2026-02-21...",   │
│           ...                           │
│         }                               │
│       ],                                │
│       "count": 30                       │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Parse and process each indicator    │
└─────────────────────────────────────────┘
    │
    ▼
Continue with threat processing workflow...
```

---

### 2. Google Gemini AI Integration

```
┌─────────────────────────────────────────────────────────┐
│          GOOGLE GEMINI AI INTEGRATION                    │
└─────────────────────────────────────────────────────────┘

Threat requires analysis
    │
    ▼
┌─────────────────────────────────────────┐
│  1. Initialize Gemini client:           │
│     import google.generativeai as genai │
│     genai.configure(api_key=GEMINI_KEY) │
│     model = genai.GenerativeModel(      │
│         "gemini-1.5-flash"              │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Build prompt for summarization:     │
│     prompt = f"""                       │
│     Analyze this cyber threat indicator:│
│                                         │
│     Indicator: {indicator_value}        │
│     Type: {indicator_type}              │
│     Tags: {tags}                        │
│     Pulse Title: {pulse_title}          │
│                                         │
│     Provide a concise 50-word summary   │
│     for a CTI analyst, including:       │
│     - Threat actor/campaign             │
│     - Attack vector                     │
│     - Target sector                     │
│     - Risk level                        │
│     """                                 │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  3. Send to Gemini API:                 │
│     response = model.generate_content(  │
│         prompt                          │
│     )                                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Gemini responds with summary:       │
│     "Russian APT28 group command and    │
│      control server targeting financial │
│      institutions in Europe. Uses       │
│      advanced persistent threat tactics.│
│      High risk - immediate blocking     │
│      recommended."                      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Extract and store summary           │
└─────────────────────────────────────────┘
    │
    ▼
Continue with threat storage...

Error Handling:
    - Rate limit exceeded → Use cached fallback
    - API timeout → Generate basic summary
    - Invalid response → Use default template
```

---

## 🎬 System Startup Workflow

### Complete System Initialization

```
┌──────────────────────────────────────────────────────────┐
│              SYSTEM STARTUP SEQUENCE                      │
└──────────────────────────────────────────────────────────┘

STEP 1: Backend Initialization
    │
    ▼
┌─────────────────────────────────────────┐
│  1. PowerShell as Administrator:        │
│     cd backend                          │
│     .\.venv\Scripts\Activate.ps1        │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  2. Start Flask app:                    │
│     python app.py                       │
│                                         │
│  A. Load environment variables:         │
│     - SECRET_KEY                        │
│     - API_KEY (OTX)                     │
│     - GEMINI_API_KEY                    │
│     - MAIL_USERNAME, MAIL_PASSWORD      │
│                                         │
│  B. Initialize database:                │
│     - Create tables if not exist        │
│     - Run migrations                    │
│     - Create admin user if needed       │
│                                         │
│  C. Initialize AI clients:              │
│     - init_summarizer(GEMINI_API_KEY)   │
│     - init_scorer(GEMINI_API_KEY)       │
│                                         │
│  D. Start Flask server:                 │
│     * Running on http://127.0.0.1:5000  │
│                                         │
│  E. Start background services:          │
│     - Threat Fetcher (120s intervals)   │
│     - Auto-Blocker                      │
│     - Email Notifier                    │
└─────────────────────────────────────────┘
    │
    ▼
STEP 2: Frontend Initialization
    │
    ▼
┌─────────────────────────────────────────┐
│  3. New terminal (normal user):         │
│     cd frontend                         │
│     npm start                           │
│                                         │
│  A. Load React app:                     │
│     - Parse config.js                   │
│     - Set API_BASE_URL                  │
│                                         │
│  B. Start dev server:                   │
│     * Running on http://localhost:3000  │
│     * Webpack compiled                  │
│                                         │
│  C. Open browser automatically          │
└─────────────────────────────────────────┘
    │
    ▼
STEP 3: WebSocket Connection
    │
    ▼
┌─────────────────────────────────────────┐
│  4. Start WebSocket server:             │
│     python backend/websocket_server.py  │
│                                         │
│     * WebSocket server on port 8080     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  5. Frontend connects:                  │
│     ws = new WebSocket(                 │
│         'ws://localhost:8080'           │
│     )                                   │
│     ws.onopen = () => {                 │
│         console.log('Connected')        │
│     }                                   │
└─────────────────────────────────────────┘
    │
    ▼
STEP 4: System Ready
    │
    ▼
┌─────────────────────────────────────────┐
│  ✅ SYSTEM OPERATIONAL                  │
│                                         │
│  Services Running:                      │
│  ✓ Flask API: http://127.0.0.1:5000    │
│  ✓ React App: http://localhost:3000    │
│  ✓ WebSocket: ws://localhost:8080      │
│  ✓ Threat Fetcher: Active              │
│  ✓ Auto-Blocker: Active                │
│  ✓ Email Service: Active                │
│                                         │
│  Default Admin:                         │
│  Username: admin                        │
│  Password: admin123                     │
└─────────────────────────────────────────┘
```

---

## 📋 Summary

This workflow guide covers:

1. **User Workflows**: Registration, login, threat viewing, IP blocking, subscriptions
2. **Threat Processing**: Complete lifecycle from collection to storage
3. **Auto-Blocking**: Automated firewall rule creation for high-risk IPs
4. **Email Notifications**: Alert delivery with one-click block actions
5. **Admin Workflows**: Global blocking, user management, audit logs
6. **Data Flow**: Real-time updates via WebSocket
7. **Integrations**: OTX API and Gemini AI workflows
8. **System Startup**: Complete initialization sequence

All workflows include:
- ✅ Success paths
- ❌ Error handling
- 🔄 Alternative flows
- 📊 Data validation
- 🔐 Security checks
- 📝 Audit logging

---

**Document Version**: 1.0  
**Last Updated**: February 21, 2026  
**Status**: Complete
