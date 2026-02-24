# 🛡️ Cyber Threat Intelligence (CTI) Auto-Defense System - Complete Methodology

## 📋 Executive Summary

This document provides a comprehensive methodology for the **Cyber Threat Intelligence (CTI) Auto-Defense System**, an intelligent threat detection and automated response platform that integrates real-time threat intelligence, AI-powered analysis, automated firewall blocking, and email notification workflows.

**Core Purpose**: Proactively defend against cyber threats by fetching real-time threat indicators, analyzing their risk level, notifying stakeholders, and automatically blocking malicious IPs.

---

## 🎯 Project Overview

### **Problem Statement**
Organizations face continuous cyber threats from malicious IPs, domains, and indicators. Manual threat monitoring and response is:
- **Time-consuming**: Analysts must manually review thousands of indicators
- **Reactive**: Threats are often detected after damage occurs
- **Inconsistent**: Human error leads to missed threats or false positives
- **Unscalable**: Cannot keep pace with the volume of modern threats

### **Solution**
An automated CTI platform that:
1. **Fetches** real-time threat intelligence from AlienVault OTX
2. **Analyzes** threats using Google Gemini AI for contextual understanding
3. **Scores** threats based on severity (0-100 risk scale)
4. **Notifies** users via email with actionable intelligence
5. **Blocks** high-risk IPs automatically via Windows Firewall
6. **Audits** all actions for compliance and forensics

---

## 🏗️ System Architecture

### **1. Three-Tier Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend Layer                          │
│  React.js Dashboard + WebSocket Real-time Updates          │
│  - Threat Visualization   - User Management                │
│  - IP Blocking Controls   - Email Preferences              │
└─────────────────────────────────────────────────────────────┘
                            ↕ HTTP/REST API
┌─────────────────────────────────────────────────────────────┐
│                     Backend Layer                           │
│  Flask REST API + Background Services                       │
│  - Threat Fetcher   - AI Analyzer  - Email Notifier        │
│  - Auto-Blocker     - IP Manager   - WebSocket Server       │
└─────────────────────────────────────────────────────────────┘
                            ↕ ORM
┌─────────────────────────────────────────────────────────────┐
│                     Data Layer                              │
│  SQLAlchemy ORM + SQLite Database                           │
│  - User DB  - Threat DB  - Blocked IP DB  - Audit Logs     │
└─────────────────────────────────────────────────────────────┘
                            ↕ Integration
┌─────────────────────────────────────────────────────────────┐
│                  External Integrations                      │
│  - AlienVault OTX API  - Google Gemini AI                  │
│  - Windows Firewall    - SMTP Email Server                  │
└─────────────────────────────────────────────────────────────┘
```

### **2. Component Architecture**

#### **Frontend (React.js)**
- **Technology**: React 18, Material-UI, Axios
- **Components**:
  - `Dashboard`: Main threat visualization dashboard
  - `ThreatsList`: Real-time threat feed with filtering
  - `BlockedIPsTable`: Manage blocked IP addresses
  - `SubscriptionSettings`: Configure email preferences
  - `AdminPanel`: Admin controls for global blocking
  - `Login/Register`: User authentication flows

#### **Backend (Flask Python)**
- **Technology**: Flask, SQLAlchemy, Flask-Mail, Flask-CORS
- **Services**:
  - **Threat Fetcher**: Polls AlienVault OTX API every 120 seconds
  - **AI Analyzer**: Gemini AI for threat summarization & scoring
  - **Email Notifier**: HTML emails with one-click block actions
  - **Auto-Blocker**: Automated IP blocking for high-risk threats
  - **IP Manager**: Windows Firewall rule creation/deletion
  - **WebSocket Server**: Real-time updates to connected clients

#### **Database (SQLite + SQLAlchemy)**
- **Models**:
  - `User`: Authentication & authorization
  - `ThreatIndicator`: Processed threat intelligence
  - `BlockedThreat`: Active IP blocks
  - `ThreatSubscription`: Email notification preferences
  - `Notification`: In-app notification history
  - `ThreatActionLog`: Audit trail
  - `MonitoredWebsite`: Website monitoring (future)

---

## 🔄 Data Flow & System Workflow

### **Phase 1: Threat Intelligence Collection**

```
AlienVault OTX API
    ↓
[Threat Fetcher Service]
    ↓ (Every 120 seconds)
Fetch latest indicators:
- IPv4 Addresses
- Domains/URLs
- File Hashes
- CVEs
    ↓
Raw JSON Response
```

**Implementation**: `backend/fetch_realtime_threats.py`
- Polls OTX `/api/v1/indicators/export` endpoint
- Applies filters: `types=FileHash-SHA256,IPv4,domain`
- Pagination: Processes 100 indicators per batch
- Rate limiting: Respects API quotas

### **Phase 2: Threat Enrichment & Intelligence Analysis**

```
Raw Threat Data
    ↓
[AI Summarization Module]
    ↓ (Google Gemini API)
Generate human-readable summary:
"Russian APT group targeting financial institutions..."
    ↓
[AI Scoring Module]
    ↓ (Gemini + Heuristics)
Calculate risk score (0-100):
- Pulse confidence
- Reference count
- Indicator age/recency
- Reputation signals
    ↓
[Categorization Engine]
    ↓
Assign category:
- Phishing, Ransomware, Malware
- DDoS, Exploits, Current Threats
    ↓
Enriched Threat Intelligence
```

**Implementation**: 
- `backend/summarizer.py`: AI-powered threat summarization
- `backend/scorer.py`: Multi-factor risk scoring algorithm
- `backend/app.py:categorize_indicator()`: Tag-based categorization

**Scoring Algorithm**:
```python
score = base_random_score(20-95)  # Ensures distribution
score += (avg_confidence / 100) * 10  # Confidence boost
score += min(references_count, 5)     # References boost
score += recency_bonus(0-30)          # Age factor

if score >= 75: severity = "High"
elif score >= 50: severity = "Medium"
else: severity = "Low"
```

### **Phase 3: Deduplication & Storage**

```
Enriched Threat
    ↓
[Deduplication Check]
    ↓
Check if indicator already exists:
- By indicator_value (IP/domain/hash)
- By otx_id (AlienVault unique ID)
    ↓
If NEW → Insert into ThreatIndicator table
If EXISTS → Update last_seen timestamp
    ↓
[Database Storage]
SQLite: instance/users.db
```

**Implementation**: `backend/app.py:ThreatIndicator` model
- Unique constraint on `indicator_value`
- Indexed on `last_seen` for efficient queries
- Stores full threat context for future analysis

### **Phase 4: Email Notification Workflow**

```
High-Risk Threat (score >= 75)
    ↓
[Check User Subscriptions]
    ↓
Query ThreatSubscription table:
- is_active = True
- min_risk_score <= threat_score
    ↓
For each subscribed user:
    ↓
[Generate Email Token]
    ↓
Create one-time block token:
token = secrets.token_urlsafe(32)
Store: {user_id, ip, threat_data, timestamp}
    ↓
[Render HTML Email]
    ↓
Template: email_service.py
- Threat summary & details
- Risk score badge
- "Block IP" action button
- Unsubscribe link
    ↓
[Send via SMTP]
    ↓
Gmail SMTP (TLS 587)
- Retry on failure
- Log success/failure
    ↓
[Store Notification]
    ↓
Save to Notification table for in-app fallback
```

**Implementation**: `backend/email_service.py`
- **Free Users**: Basic threat info
- **Premium Users**: Extended details + prevention hints
- **One-Click Block**: `https://domain/block-threat?token=xxx`

**Email Security**:
- Tokens expire after 24 hours
- One-time use only (deleted after use)
- User authentication required for token validation

### **Phase 5: Automated IP Blocking**

```
High-Risk IP Threat (score >= 75)
    ↓
[Auto-Block Service]
    ↓
Check if AUTO_BLOCK_ENABLED=true
    ↓
[Extract IP Address]
    ↓
Validate IP format:
- IPv4: 192.168.1.1
- Extract from CIDR: 10.0.0.0/24
    ↓
[Create Firewall Rules]
    ↓
Windows Firewall (netsh commands):
1. INBOUND rule: Block incoming from IP
2. OUTBOUND rule: Block outgoing to IP
    ↓
Rule names:
- ThreatGuard_Block_IN_192_168_1_1
- ThreatGuard_Block_OUT_192_168_1_1
    ↓
[Database Record]
    ↓
Insert into BlockedThreat table:
- ip_address, user_id, risk_score
- blocked_by='admin', is_active=True
    ↓
[Audit Log]
    ↓
ThreatActionLog: action='auto_block'
```

**Implementation**: `backend/ip_blocker.py`
- Requires **Administrator privileges**
- Two firewall rules per IP (IN + OUT)
- Supports manual unblocking via dashboard

**Firewall Commands**:
```powershell
# Inbound block
netsh advfirewall firewall add rule ^
  name="ThreatGuard_Block_IN_192_168_1_1" ^
  dir=in action=block remoteip=192.168.1.1

# Outbound block
netsh advfirewall firewall add rule ^
  name="ThreatGuard_Block_OUT_192_168_1_1" ^
  dir=out action=block remoteip=192.168.1.1
```

### **Phase 6: Real-Time Dashboard Updates**

```
New Threat / Block Action
    ↓
[WebSocket Broadcast]
    ↓
Send event to all connected clients:
- Event: "threat_update"
- Payload: {threat_data, action, timestamp}
    ↓
[React Frontend]
    ↓
Update UI components:
- ThreatsList: Add new threat
- BlockedIPsTable: Add blocked IP
- Dashboard stats: Increment counters
```

**Implementation**: `backend/websocket_server.py` + React hooks
- WebSocket port: 8080
- Auto-reconnect on disconnect
- JSON event protocol

---

## 🛠️ Technology Stack

### **Frontend Technologies**
| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18.x | UI framework |
| Material-UI | 5.x | Component library |
| Axios | 1.x | HTTP client |
| WebSocket API | Native | Real-time updates |
| React Router | 6.x | Client-side routing |

### **Backend Technologies**
| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.9+ | Core language |
| Flask | 2.3.x | Web framework |
| SQLAlchemy | 2.x | ORM |
| Flask-Mail | 0.9.x | Email service |
| Flask-CORS | 4.x | Cross-origin support |
| Flask-Migrate | 4.x | Database migrations |
| PyJWT | 2.x | Token authentication |
| Requests | 2.x | HTTP client |
| Google Generative AI | 0.3.x | Gemini API client |

### **External Services**
| Service | Purpose | API Endpoint |
|---------|---------|--------------|
| AlienVault OTX | Threat intelligence | `otx.alienvault.com/api/v1` |
| Google Gemini | AI analysis | `generativelanguage.googleapis.com` |
| Gmail SMTP | Email delivery | `smtp.gmail.com:587` |
| Windows Firewall | IP blocking | `netsh advfirewall` (local) |

### **Development Tools**
- **Version Control**: Git
- **Containerization**: Docker + Docker Compose
- **Package Management**: npm (frontend), pip (backend)
- **Environment Management**: Python venv
- **Database**: SQLite (dev), PostgreSQL (production-ready)

---

## 🔐 Security Architecture

### **1. Authentication & Authorization**

#### **JWT Token-Based Auth**
```python
# Login flow
User submits credentials
    ↓
Backend validates password (Werkzeug PBKDF2 hashing)
    ↓
Generate JWT token:
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    ↓
Frontend stores token in localStorage
    ↓
All API requests include: Authorization: Bearer {token}
```

#### **Role-Based Access Control (RBAC)**
| Role | Permissions |
|------|-------------|
| **user** | View own threats, block own IPs, manage subscriptions |
| **admin** | All user permissions + global IP blocking + user management |

**Decorator Implementation**:
```python
@app.route('/admin/block-ip', methods=['POST'])
@token_required
@admin_required
def admin_block_ip():
    # Only admins can execute
```

### **2. Data Protection**

#### **Password Security**
- **Hashing**: Werkzeug `pbkdf2:sha256` with salt
- **Minimum Length**: 8 characters
- **Storage**: Never stored in plaintext

#### **API Key Management**
- Stored in `.env` file (never committed to Git)
- Environment variables loaded via `python-dotenv`
- Keys:
  - `SECRET_KEY`: JWT signing
  - `GEMINI_API_KEY`: AI services
  - `API_KEY`: AlienVault OTX
  - `MAIL_PASSWORD`: SMTP authentication

#### **SQL Injection Prevention**
- SQLAlchemy ORM with parameterized queries
- No raw SQL execution
- Input validation on all endpoints

### **3. Network Security**

#### **CORS Configuration**
```python
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

#### **Rate Limiting**
- Flask-Limiter on auth endpoints
- `/login`: 5 requests per minute
- `/register`: 3 requests per minute
- Prevents brute-force attacks

#### **HTTPS Enforcement**
- Production: Flask-Talisman with strict CSP
- Development: Disabled for localhost testing

### **4. Input Validation**

#### **IP Address Validation**
```python
def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)
```

#### **Email Validation**
- Regex pattern for email format
- Domain MX record verification (optional)

### **5. Audit Logging**

All security-critical actions logged to `ThreatActionLog`:
- User authentication attempts
- IP blocking/unblocking
- Email notifications sent
- Admin actions

**Log Fields**:
```python
{
    'user_id': int,
    'action': str,  # 'login', 'block_ip', 'unblock_ip', 'send_email'
    'ip_address': str,
    'details': json,
    'timestamp': datetime,
    'success': bool
}
```

---

## 🧪 Testing Strategy

### **1. Unit Testing**

#### **Backend Tests**
```python
# test_threat_processing.py
def test_categorize_indicator():
    """Test threat categorization logic"""
    indicator = {'tags': ['phishing'], 'type': 'url'}
    category = categorize_indicator(indicator)
    assert category == 'Phishing'

def test_severity_scoring():
    """Test risk score calculation"""
    indicator = {'pulse_info': {'pulses': [{'confidence': 85}]}}
    result = compute_severity_score(indicator)
    assert 0 <= result['severity_score'] <= 100
    assert result['severity'] in ['Low', 'Medium', 'High']

def test_ip_validation():
    """Test IP address validation"""
    assert is_valid_ip('192.168.1.1') == True
    assert is_valid_ip('999.999.999.999') == False
    assert is_valid_ip('not-an-ip') == False
```

#### **Test Files**
- `test_login.py`: User authentication flows
- `test_block_endpoint.py`: IP blocking API
- `test_deactivate_endpoint.py`: Token deactivation
- `test_balanced_threats.py`: Threat distribution
- `verify_threats.py`: OTX API integration

**Run Tests**:
```bash
pytest backend/tests/ -v --cov=backend
```

### **2. Integration Testing**

#### **API Endpoint Tests**
```python
# test_api_integration.py
def test_fetch_threats_endpoint(client):
    """Test /api/threats endpoint"""
    token = get_admin_token()
    response = client.get('/api/threats', 
                         headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    data = response.json
    assert 'threats' in data
    assert isinstance(data['threats'], list)

def test_block_ip_workflow(client):
    """Test complete IP blocking workflow"""
    # 1. Fetch threat
    # 2. Block IP
    # 3. Verify firewall rule
    # 4. Verify database record
```

#### **External API Tests**
- `test_otx_api.py`: AlienVault OTX connectivity
- `test_gemini_api.py`: Google Gemini responses
- `test_email_delivery.py`: SMTP functionality

### **3. System Testing**

#### **End-to-End Scenarios**
1. **New Threat Detection**:
   - Start threat fetcher
   - Wait for new threat (score >= 75)
   - Verify email sent
   - Verify database entry
   - Verify dashboard update

2. **Auto-Block Workflow**:
   - Identify high-risk IP
   - Trigger auto-block
   - Verify firewall rules created
   - Verify blocking works (ping test)
   - Unblock IP
   - Verify rules removed

3. **User Journey**:
   - Register new user
   - Login
   - Subscribe to email alerts
   - Receive notification
   - Click "Block IP" in email
   - Verify IP blocked in dashboard

#### **Test Scripts**
- `verify_live_system.py`: Production health check
- `check_ip_blocked.ps1`: Firewall rule verification
- `test_block_comprehensive.py`: Full blocking test suite

### **4. Performance Testing**

#### **Load Testing**
- Simulate 1000 concurrent threats
- Measure processing time per indicator
- Target: <500ms per threat
- Tool: `locust` or `pytest-benchmark`

#### **Database Performance**
- Index optimization: `indicator_value`, `last_seen`
- Query performance: <100ms for dashboard queries
- Bulk insert: 100 threats in <2 seconds

#### **Email Throughput**
- Test: Send 100 emails
- Target: <30 seconds total
- SMTP connection pooling
- Async email sending (optional)

---

## 🚀 Deployment Methodology

### **Phase 1: Development Environment Setup**

#### **Prerequisites**
- Python 3.9+
- Node.js 16+
- Git
- Windows (for firewall integration)

#### **Backend Setup**
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Edit .env with real API keys

# Initialize database
flask db upgrade

# Create admin user
python create_admin.py
```

#### **Frontend Setup**
```powershell
cd frontend
npm install
npm start
```

### **Phase 2: Docker Containerization**

#### **Docker Compose Architecture**
```yaml
version: "3.9"
services:
  backend:
    build: ./backend
    ports: ["5000:5000"]
    volumes:
      - backend-instance:/app/instance
    env_file: ./backend/.env
    networks: [appnet]

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    depends_on: [backend]
    networks: [appnet]

networks:
  appnet: {}
volumes:
  backend-instance: {}
```

#### **Build & Deploy**
```powershell
docker-compose build
docker-compose up -d
docker-compose logs -f
```

### **Phase 3: Production Deployment (Windows Server)**

#### **1. Server Configuration**
- Windows Server 2019/2022
- IIS or standalone Flask
- PostgreSQL (replace SQLite)
- SSL certificate (Let's Encrypt)

#### **2. Backend Deployment**
```powershell
# Install as Windows Service
.\install_service.ps1

# Service configuration
Service Name: ThreatGuardBackend
Startup Type: Automatic
Recovery: Restart on failure
```

#### **3. Frontend Deployment**
```powershell
npm run build
# Copy build/ to IIS wwwroot
# Configure reverse proxy to backend:5000
```

#### **4. Firewall Configuration**
```powershell
# Allow backend port
New-NetFirewallRule -DisplayName "ThreatGuard API" `
  -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow

# Enable Windows Firewall API access
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### **Phase 4: Production Monitoring**

#### **Health Checks**
```python
@app.route('/health')
def health_check():
    """System health endpoint"""
    return jsonify({
        'status': 'healthy',
        'database': db_status(),
        'otx_api': otx_api_status(),
        'firewall': firewall_status(),
        'timestamp': datetime.utcnow().isoformat()
    })
```

#### **Monitoring Dashboards**
- **Uptime**: Pingdom, UptimeRobot
- **Logs**: Centralized via Syslog or Splunk
- **Metrics**: Prometheus + Grafana
- **Alerts**: Email/SMS on service failure

#### **Backup Strategy**
```powershell
# Daily database backup
$date = Get-Date -Format "yyyyMMdd"
Copy-Item "instance\users.db" "backups\users_$date.db"

# Backup firewall rules
netsh advfirewall export "backups\firewall_rules_$date.wfw"
```

---

## 📊 Database Schema

### **Entity-Relationship Diagram**

```
┌─────────────┐       ┌──────────────────┐
│    User     │───┬───│ ThreatSubscription│
│             │   │   └──────────────────┘
│ - id (PK)   │   │
│ - username  │   │   ┌──────────────────┐
│ - email     │   ├───│  BlockedThreat   │
│ - role      │   │   │                  │
│ - subscription   │   │ - ip_address     │
└─────────────┘   │   │ - blocked_by     │
                  │   │ - is_active      │
                  │   └──────────────────┘
                  │
                  │   ┌──────────────────┐
                  ├───│  Notification    │
                  │   │                  │
                  │   │ - subject        │
                  │   │ - body           │
                  │   │ - is_read        │
                  │   └──────────────────┘
                  │
                  │   ┌──────────────────┐
                  └───│ ThreatActionLog  │
                      │                  │
                      │ - action         │
                      │ - ip_address     │
                      │ - details (JSON) │
                      └──────────────────┘

┌──────────────────────┐
│  ThreatIndicator     │
│                      │
│ - indicator_value(PK)│
│ - indicator_type     │
│ - category           │
│ - severity           │
│ - score              │
│ - summary            │
│ - last_seen          │
└──────────────────────┘
```

### **Table Definitions**

#### **User Table**
```sql
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(10) DEFAULT 'user',
    subscription VARCHAR(20) DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### **ThreatIndicator Table**
```sql
CREATE TABLE threat_indicator (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_value VARCHAR(500) UNIQUE NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    score FLOAT DEFAULT 0.0,
    summary VARCHAR(500),
    pulse_count INTEGER DEFAULT 0,
    reputation FLOAT DEFAULT 0.0,
    last_activity DATETIME,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    otx_id VARCHAR(100) UNIQUE,
    INDEX idx_last_seen (last_seen),
    INDEX idx_indicator_value (indicator_value)
);
```

#### **BlockedThreat Table**
```sql
CREATE TABLE blocked_threat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    risk_category VARCHAR(20) NOT NULL,
    risk_score FLOAT NOT NULL,
    summary VARCHAR(500),
    blocked_by VARCHAR(20) NOT NULL,
    blocked_by_user_id INTEGER,
    reason VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    unblocked_at DATETIME,
    unblocked_by_user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (blocked_by_user_id) REFERENCES user(id),
    FOREIGN KEY (unblocked_by_user_id) REFERENCES user(id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_blocked_at (blocked_at)
);
```

---

## 🔧 Configuration Management

### **Environment Variables (.env)**

```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=production
DEBUG=False

# Database
DATABASE_URL=sqlite:///users.db
# Production: postgresql://user:pass@host:5432/dbname

# AlienVault OTX API
API_KEY=your-otx-api-key
API_URL=https://otx.alienvault.com/api/v1/indicators/export

# Google Gemini AI
GEMINI_API_KEY=your-gemini-api-key

# Email Configuration (Gmail)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Threat Processing
NOTIFY_THRESHOLD=80
AUTO_BLOCK_THRESHOLD=75
AUTO_BLOCK_ENABLED=true
THREATS_POLL_INTERVAL=120
THREATS_LIMIT=30

# Security
ENABLE_HARDENING=true
AGENT_API_TOKEN=your-agent-token
AGENT_REQUIRE_TOKEN=true
```

### **Frontend Configuration (frontend/src/config.js)**

```javascript
export const API_BASE_URL = process.env.REACT_APP_API_ORIGIN || 'http://localhost:5000';
export const WEBSOCKET_URL = 'ws://localhost:8080';
export const APP_NAME = 'CTI Auto-Defense System';
export const VERSION = '1.0.0';
```

---

## 📈 Operational Procedures

### **Daily Operations**

#### **1. System Health Check**
```powershell
# Check backend status
curl http://localhost:5000/health

# Check firewall rules count
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard" | Measure-Object

# Check database size
Get-ChildItem instance\users.db | Select-Object Name, Length
```

#### **2. Threat Review**
- Login to admin dashboard
- Review "High" severity threats from last 24 hours
- Investigate anomalies (unusual IPs, false positives)
- Manually block/unblock as needed

#### **3. Email Notifications**
- Check `ThreatActionLog` for email failures
- Verify SMTP credentials if failures detected
- Review user subscription preferences

### **Weekly Operations**

#### **1. Database Maintenance**
```python
# Cleanup old threats (>30 days)
python backend/cleanup_old_threats.py --days=30

# Vacuum database
sqlite3 instance/users.db "VACUUM;"
```

#### **2. User Management**
- Review new user registrations
- Assign premium subscriptions
- Disable inactive accounts

#### **3. Threat Intelligence Review**
- Analyze most common threat categories
- Identify emerging threat patterns
- Update categorization keywords if needed

### **Monthly Operations**

#### **1. Security Audit**
- Review all admin actions in `ThreatActionLog`
- Check for unauthorized access attempts
- Update API keys and secrets
- Review firewall rule list

#### **2. Performance Optimization**
- Analyze slow queries
- Rebuild database indexes
- Review and optimize API call patterns

#### **3. Backup Verification**
- Test database restore from backup
- Verify backup automation scripts
- Update disaster recovery documentation

---

## 🐛 Troubleshooting Guide

### **Common Issues**

#### **Issue 1: IP Blocking Not Working**
**Symptom**: IPs show as "blocked" but traffic still flows

**Diagnosis**:
```powershell
# Check if backend has admin privileges
whoami /priv | Select-String "SeDebugPrivilege"

# Verify firewall rules exist
netsh advfirewall firewall show rule name="ThreatGuard_Block_IN_192_168_1_1"

# Test connectivity to blocked IP
ping 192.168.1.1
Test-NetConnection 192.168.1.1 -Port 443
```

**Solution**:
1. Restart backend with Administrator privileges
2. Run: `.\START_BACKEND_ADMIN.ps1`
3. Re-block IP from dashboard

#### **Issue 2: No Email Notifications**
**Symptom**: High-risk threats detected but no emails sent

**Diagnosis**:
```python
# Check email configuration
python backend/check_email_config.py

# Test SMTP connection
python backend/test_email_delivery.py
```

**Solution**:
1. Verify `.env` has correct `MAIL_USERNAME` and `MAIL_PASSWORD`
2. Enable "Less secure app access" in Gmail (or use App Password)
3. Check firewall allows port 587
4. Review logs: `backend/email_service_errors.log`

#### **Issue 3: OTX API Rate Limit**
**Symptom**: No new threats fetched, API errors in logs

**Diagnosis**:
```powershell
# Check last successful fetch
python backend/check_last_fetch.py

# Test API key
curl -H "X-OTX-API-KEY: $API_KEY" https://otx.alienvault.com/api/v1/user/me
```

**Solution**:
1. Increase `THREATS_POLL_INTERVAL` to 300 seconds
2. Verify API key is valid
3. Check OTX account quotas

#### **Issue 4: Database Locked Errors**
**Symptom**: SQLite "database is locked" errors

**Diagnosis**:
```powershell
# Check for file locks
Get-Process | Where-Object {$_.Path -like "*python*"}
```

**Solution**:
1. Stop all backend processes
2. Close database file: `sqlite3 instance/users.db ".quit"`
3. Restart backend
4. Consider migrating to PostgreSQL for production

---

## 📚 API Documentation

### **Authentication Endpoints**

#### **POST /api/register**
Register new user account.

**Request**:
```json
{
    "username": "johndoe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "password": "SecurePass123!"
}
```

**Response** (201):
```json
{
    "message": "User registered successfully",
    "user_id": 42
}
```

#### **POST /api/login**
Authenticate user and receive JWT token.

**Request**:
```json
{
    "username": "johndoe",
    "password": "SecurePass123!"
}
```

**Response** (200):
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 42,
        "username": "johndoe",
        "email": "john@example.com",
        "role": "user",
        "subscription": "free"
    }
}
```

### **Threat Endpoints**

#### **GET /api/threats**
Fetch recent threats with filtering.

**Headers**: `Authorization: Bearer {token}`

**Query Parameters**:
- `category`: Filter by category (Phishing, Ransomware, etc.)
- `severity`: Filter by severity (Low, Medium, High)
- `limit`: Max results (default: 50, max: 500)
- `offset`: Pagination offset

**Response** (200):
```json
{
    "threats": [
        {
            "id": 1234,
            "indicator": "192.168.1.100",
            "type": "IPv4",
            "category": "Malware",
            "severity": "High",
            "score": 87.5,
            "summary": "Russian APT group C2 server targeting financial institutions",
            "last_seen": "2026-02-21T10:30:00Z"
        }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
}
```

#### **POST /api/block-ip**
Block an IP address.

**Headers**: `Authorization: Bearer {token}`

**Request**:
```json
{
    "ip_address": "192.168.1.100",
    "reason": "High-risk malware C2 server",
    "threat_data": {
        "threat_type": "Malware",
        "risk_score": 87.5,
        "category": "High"
    }
}
```

**Response** (200):
```json
{
    "message": "IP blocked successfully",
    "firewall_rules": [
        "ThreatGuard_Block_IN_192_168_1_100",
        "ThreatGuard_Block_OUT_192_168_1_100"
    ],
    "blocked_id": 567
}
```

#### **DELETE /api/unblock-ip/{ip_address}**
Unblock a previously blocked IP.

**Headers**: `Authorization: Bearer {token}`

**Response** (200):
```json
{
    "message": "IP unblocked successfully",
    "ip_address": "192.168.1.100"
}
```

### **Subscription Endpoints**

#### **POST /api/subscribe-notifications**
Subscribe to email threat notifications.

**Headers**: `Authorization: Bearer {token}`

**Request**:
```json
{
    "email": "john@example.com",
    "min_risk_score": 75
}
```

**Response** (200):
```json
{
    "message": "Subscribed to threat notifications",
    "subscription_id": 123
}
```

#### **DELETE /api/unsubscribe**
Unsubscribe from email notifications.

**Headers**: `Authorization: Bearer {token}`

**Response** (200):
```json
{
    "message": "Unsubscribed successfully"
}
```

---

## 🎓 Best Practices & Recommendations

### **Security Best Practices**

1. **Never Commit Secrets**
   - Use `.env` files (add to `.gitignore`)
   - Use environment variables in CI/CD
   - Rotate API keys quarterly

2. **Principle of Least Privilege**
   - Regular users: Limited to own data
   - Admins: Global access, audit logged
   - Service accounts: Minimum required permissions

3. **Input Validation Everywhere**
   - Validate IP addresses before blocking
   - Sanitize user inputs
   - Use ORM (SQLAlchemy) to prevent SQL injection

4. **Regular Security Audits**
   - Review `ThreatActionLog` weekly
   - Monitor failed authentication attempts
   - Keep dependencies updated (`pip-audit`, `npm audit`)

### **Performance Best Practices**

1. **Database Optimization**
   - Index frequently queried columns (`last_seen`, `ip_address`)
   - Use pagination for large result sets
   - Consider PostgreSQL for production (better concurrency)

2. **API Rate Limiting**
   - Respect AlienVault OTX quotas
   - Cache API responses (Redis)
   - Implement exponential backoff on failures

3. **Async Processing**
   - Use background tasks for email sending (Celery)
   - WebSocket for real-time updates (avoid polling)
   - Queue-based IP blocking (prevent race conditions)

### **Operational Best Practices**

1. **Monitoring & Alerting**
   - Set up uptime monitoring (UptimeRobot)
   - Alert on high error rates (>5% in 5 minutes)
   - Monitor disk space (database growth)

2. **Backup Strategy**
   - Daily automated database backups
   - Backup retention: 30 days
   - Test restore procedure monthly

3. **Documentation**
   - Keep runbooks updated
   - Document all configuration changes
   - Maintain API changelog

---

## 🚦 Future Enhancements

### **Phase 1: Core Improvements**
- [ ] PostgreSQL migration for production scalability
- [ ] Redis caching for API responses
- [ ] Celery for asynchronous task processing
- [ ] WebSocket authentication & encryption

### **Phase 2: Advanced Features**
- [ ] Machine learning for threat prediction
- [ ] Custom threat intelligence feeds (beyond OTX)
- [ ] Automated threat hunting workflows
- [ ] Integration with SIEM platforms (Splunk, ELK)

### **Phase 3: Enterprise Features**
- [ ] Multi-tenancy support
- [ ] Custom alerting rules engine
- [ ] Threat intelligence sharing (STIX/TAXII)
- [ ] Compliance reporting (GDPR, SOC 2)

### **Phase 4: Platform Expansion**
- [ ] Mobile app (iOS/Android)
- [ ] Browser extension for inline threat lookup
- [ ] CLI tool for power users
- [ ] API SDK (Python, JavaScript, Go)

---

## 📞 Support & Maintenance

### **Support Contacts**
- **Technical Issues**: support@threatguard.local
- **Security Concerns**: security@threatguard.local
- **Feature Requests**: feedback@threatguard.local

### **Maintenance Windows**
- **Weekly**: Sundays 2:00 AM - 4:00 AM (UTC)
- **Monthly**: First Sunday 2:00 AM - 6:00 AM (UTC)

### **SLA Targets**
- **Uptime**: 99.5% (excluding maintenance)
- **API Response Time**: <500ms (p95)
- **Email Delivery**: <2 minutes from threat detection
- **Auto-Block Latency**: <30 seconds

---

## 📖 Glossary

| Term | Definition |
|------|------------|
| **OTX** | AlienVault Open Threat Exchange - community threat intelligence platform |
| **Indicator** | Observable artifact of a threat (IP, domain, hash, URL) |
| **Pulse** | Collection of related threat indicators in OTX |
| **C2 Server** | Command and Control server used by attackers |
| **APT** | Advanced Persistent Threat - sophisticated, long-term attack campaign |
| **IOC** | Indicator of Compromise - evidence of security breach |
| **STIX/TAXII** | Standards for threat intelligence sharing |
| **Severity** | Risk level: Low (<50), Medium (50-75), High (>=75) |
| **Auto-Block** | Automated IP blocking for high-risk threats |
| **One-Time Token** | Secure link for email-based IP blocking |

---

## 📄 Appendix

### **A. File Structure**
```
Final_Project/
├── backend/
│   ├── app.py                    # Main Flask application
│   ├── summarizer.py             # Gemini AI summarization
│   ├── scorer.py                 # Risk scoring algorithm
│   ├── ip_blocker.py             # Windows Firewall integration
│   ├── email_service.py          # Email notification service
│   ├── websocket_server.py       # Real-time updates
│   ├── threat_processor.py       # Threat normalization
│   ├── fetch_realtime_threats.py # OTX API polling
│   ├── requirements.txt          # Python dependencies
│   └── instance/
│       └── users.db              # SQLite database
├── frontend/
│   ├── src/
│   │   ├── App.js                # Main React component
│   │   ├── components/           # React components
│   │   ├── api.js                # API client
│   │   └── config.js             # Configuration
│   ├── public/
│   └── package.json              # Node dependencies
├── docker-compose.yml            # Docker orchestration
├── README.md                     # Quick start guide
└── PROJECT_METHODOLOGY.md        # This document
```

### **B. Command Reference**

#### **Backend Commands**
```powershell
# Run as administrator
.\START_BACKEND_ADMIN.ps1

# Database migrations
flask db init
flask db migrate -m "description"
flask db upgrade

# Create admin user
python create_admin.py

# Check system health
python verify_live_system.py

# Clean old threats
python backend/cleanup_old_threats.py --days=30
```

#### **Frontend Commands**
```powershell
# Development server
npm start

# Production build
npm run build

# Run tests
npm test

# Lint code
npm run lint
```

#### **Docker Commands**
```powershell
# Build containers
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down

# Restart service
docker-compose restart backend
```

#### **Firewall Commands**
```powershell
# List ThreatGuard rules
netsh advfirewall firewall show rule name=all | Select-String "ThreatGuard"

# Delete all ThreatGuard rules
netsh advfirewall firewall delete rule name="ThreatGuard_Block_IN" /all
netsh advfirewall firewall delete rule name="ThreatGuard_Block_OUT" /all

# Export firewall config
netsh advfirewall export "firewall_backup.wfw"

# Import firewall config
netsh advfirewall import "firewall_backup.wfw"
```

### **C. Key Metrics to Monitor**

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| System Uptime | 99.5% | <95% |
| API Response Time (p95) | <500ms | >2000ms |
| Database Size | <1GB | >5GB |
| Error Rate | <1% | >5% |
| Threats Processed/Day | >100 | <10 |
| Emails Sent/Day | >20 | 0 |
| Active Blocked IPs | 10-100 | >1000 |
| Failed Login Attempts | <10/hour | >50/hour |

---

## ✅ Conclusion

This **Cyber Threat Intelligence Auto-Defense System** provides a comprehensive, automated solution for real-time threat detection and response. By combining threat intelligence, AI analysis, automated blocking, and proactive notifications, the platform enables organizations to:

1. **Detect** threats faster through continuous monitoring
2. **Analyze** threats intelligently using AI-powered risk scoring
3. **Respond** automatically with firewall-level IP blocking
4. **Communicate** effectively via targeted email notifications
5. **Audit** all actions for compliance and forensics

The methodology outlined in this document provides a complete roadmap for development, deployment, operation, and maintenance of the system. Follow these guidelines to ensure security, reliability, and scalability of the platform.

---

**Document Version**: 1.0  
**Last Updated**: February 21, 2026  
**Author**: CTI Auto-Defense Development Team  
**Status**: Production Ready
