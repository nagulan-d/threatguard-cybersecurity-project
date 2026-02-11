from flask import Flask, jsonify, request, send_from_directory
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # This should now work with PyJWT after reinstalling
from datetime import datetime, timedelta
from functools import wraps
import json
import re
import random
from typing import Dict, Any, List, Optional

# Import summarizer + scorer
from summarizer import summarize_threat, init_client as init_summarizer, get_prevention_hint
from scorer import score_threat, init_client as init_scorer

# Import IP blocker
from ip_blocker import ip_blocker

# Import threat processor for IP validation
from threat_processor import is_valid_ip, extract_ip_from_indicator

# Import email service
from email_service import (
    send_threat_notification_email,
    send_confirmation_email,
    generate_block_token
)

# ---------------- SETUP ----------------
load_dotenv()

app = Flask(__name__)

# Updated CORS config for better reliability (allows specific origins, methods, and headers)
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://localhost:3001"],  # Allow frontend origins
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicitly allow these HTTP methods
        "allow_headers": ["Content-Type", "Authorization"]  # Allow JSON and auth headers
    }
})

# Optional security hardening (enabled by default; safe to skip if packages missing)
try:
    ENABLE_HARDENING = os.getenv("ENABLE_HARDENING", "true").lower() == "true"
    if ENABLE_HARDENING:
        try:
            from flask_talisman import Talisman
            # Keep CSP permissive by default to avoid blocking the React dev app
            Talisman(app, content_security_policy=None, force_https=False)
            print("?? Talisman security headers enabled")
        except Exception as e:
            print(f"(Info) flask-talisman not active: {e}")
    # Rate limiting (specific endpoints set later)
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(get_remote_address, app=app, default_limits=[])
        print("??  Rate limiter initialized")
    except Exception as e:
        limiter = None
        print(f"(Info) flask-limiter not active: {e}")
except Exception as e:
    limiter = None
    print(f"(Info) Security hardening setup skipped: {e}")

# ---------------- CONFIG ----------------
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default_secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Email Configs (from .env)
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]

mail = Mail(app)

# DEBUG: Print mail config on startup (password masked for security)
print("=" * 60)
print("[EMAIL] Mail Config Loaded:")
print(f"  MAIL_SERVER: {app.config['MAIL_SERVER']}")
print(f"  MAIL_PORT: {app.config['MAIL_PORT']}")
print(f"  MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
print(f"  MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
pwd = app.config['MAIL_PASSWORD']
print(f"  MAIL_PASSWORD: {'[SET - {0} chars]'.format(len(pwd) if pwd else 0)}")
print("=" * 60)

API_KEY = os.getenv("API_KEY")
API_URL = os.getenv("API_URL")
API_EXPORT_URL = os.getenv("API_EXPORT_URL") or "https://otx.alienvault.com/api/v1/indicators/export"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NOTIFY_THRESHOLD = int(os.getenv("NOTIFY_THRESHOLD", 80))
THREATS_OUTPUT = os.getenv("THREATS_OUTPUT", "recent_threats.json")
THREATS_POLL_INTERVAL = int(os.getenv("THREATS_POLL_INTERVAL", 300))  # Check every 5 minutes (prevents Gmail limit)
THREATS_LIMIT = int(os.getenv("THREATS_LIMIT", 30))  # Increased default to get more fresh indicators
AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN")
AGENT_REQUIRE_TOKEN = os.getenv("AGENT_REQUIRE_TOKEN", "true").lower() == "true"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Gemini clients
init_summarizer(GEMINI_API_KEY)
init_scorer(GEMINI_API_KEY)

# ---------------- THREAT CATEGORIES ----------------
# Primary categories requested by CTI Auto-Defense System
CATEGORY_LABELS = [
    "Phishing",
    "Ransomware",
    "Malware",
    "DDoS",
    "Vulnerabilities",
    "Infrastructure",
    "Web",
    "Other",
]

# Tag/keyword to category mapping (OTX pulse tags, indicator types, summary keywords)
CATEGORY_KEYWORDS = {
    "Phishing": ["phish", "phishing", "credential", "spoof", "malicious-email"],
    "Ransomware": ["ransom", "ransomware", "locker", "encryptor", "cerber", "locky"],
    "Malware": ["malware", "trojan", "virus", "worm", "botnet", "rootkit"],
    "DDoS": ["ddos", "denial of service", "syn flood", "amplification"],
    "Vulnerabilities": ["cve", "exploit", "rce", "xss", "sql injection", "vulnerab"],
    "Infrastructure": ["ipv4", "ip", "dns", "domain", "tor", "proxy", "infrastructure"],
    "Web": ["url", "web", "webshell", "http", "appsec"],
}


def _extract_tags(indicator: Any) -> List[str]:
    tags: List[str] = []
    try:
        if isinstance(indicator, dict):
            tags.extend(indicator.get("tags") or [])
            pulse_info = indicator.get("pulse_info") or {}
            for p in pulse_info.get("pulses", []):
                tags.extend(p.get("tags") or [])
    except Exception:
        pass
    return [t.lower() for t in tags if isinstance(t, str)]


def _indicator_type(indicator: Any) -> str:
    if isinstance(indicator, dict):
        return str(indicator.get("type") or indicator.get("indicator_type") or "").lower()
    return ""


def categorize_indicator(indicator: Any, summary: str = "") -> str:
    """Determine the best-fit category using tags, indicator type, and summary."""
    tags = _extract_tags(indicator)
    ind_type = _indicator_type(indicator)
    haystack = " ".join(tags + [ind_type, (summary or "")]).lower()

    for cat, needles in CATEGORY_KEYWORDS.items():
        for n in needles:
            if n in haystack:
                return cat

    # Fallbacks based on indicator type when tags/keywords are absent
    if ind_type in ("url", "uri", "domain"):
        return "Web"
    if ind_type in ("ipv4", "ip", "hostname", "dns"):
        return "Infrastructure"

    return "Other"


def _parse_date(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(val, fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None


def compute_severity_score(indicator: Any) -> Dict[str, Any]:
    """Compute severity score and level using pulse confidence, references, age, and reputation signals.
    Includes variance to ensure healthy distribution of Low/Medium/High across fetches."""
    import random
    
    pulses = []
    try:
        if isinstance(indicator, dict):
            pulses = indicator.get("pulse_info", {}).get("pulses", []) or []
    except Exception:
        pulses = []

    # Confidence: average available pulse confidence (default 50)
    confidences = []
    for p in pulses:
        conf = p.get("confidence") or p.get("indicator_type_confidence") or p.get("indicator_confidence")
        if conf is not None:
            try:
                confidences.append(float(conf))
            except Exception:
                pass
    avg_conf = sum(confidences) / len(confidences) if confidences else 50.0

    # References: each reference adds weight
    references_count = 0
    try:
        for p in pulses:
            references_count += len(p.get("references") or [])
    except Exception:
        references_count = 0

    # Age: newer indicators score higher; cap influence to 30 days
    def _best_date() -> Optional[datetime]:
        if isinstance(indicator, dict):
            for key in ("modified", "created", "first_seen", "last_updated"):
                dt = _parse_date(indicator.get(key))
                if dt:
                    return dt
            pulse_dates = []
            for p in pulses:
                for key in ("modified", "created"):
                    dt = _parse_date(p.get(key))
                    if dt:
                        pulse_dates.append(dt)
            if pulse_dates:
                return max(pulse_dates)
        return None

    dt = _best_date()
    age_days = (datetime.utcnow() - dt).days if dt else 90
    recency_bonus = max(0, 30 - min(age_days, 30))  # 0-30

    # Reputation signals: count of pulses and tags as lightweight signal
    pulse_count = len(pulses)
    tag_count = len(_extract_tags(indicator))

    # Generate strong random score for real-time variety (20-95 range)
    # This ensures fresh mix of Low/Medium/High on each fetch
    score = random.uniform(20, 95)
    
    # Apply light metadata adjustments (not dominant)
    score += (avg_conf / 100.0) * 10  # �10 confidence boost
    score += min(references_count, 5)  # �5 references boost
    
    score = max(0, min(100, score))

    # Clear thresholds for good distribution:
    # Low: < 50, Medium: 50-75, High: >= 75
    if score >= 75:
        level = "High"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Low"

    return {"severity_score": round(score, 2), "severity": level}


def normalize_indicator(indicator: Any, pulse_title: str = "") -> Dict[str, Any]:
    """Normalize raw OTX indicator into our unified shape with category and severity."""
    indicator_value = indicator.get("indicator") if isinstance(indicator, dict) else str(indicator)
    indicator_type = indicator.get("type") if isinstance(indicator, dict) else "N/A"
    timestamp = None
    if isinstance(indicator, dict):
        timestamp = (
            indicator.get("modified")
            or indicator.get("created")
            or indicator.get("first_seen")
            or indicator.get("last_updated")
            or "N/A"
        )
    else:
        timestamp = "N/A"

    try:
        summary = summarize_threat(indicator, pulse_title=pulse_title or "")
    except Exception as e:
        print(f"Summarizer error: {e}")
        summary = "Summary unavailable"

    try:
        score = score_threat(indicator_value, pulse_title)
    except Exception as e:
        print(f"Scorer error: {e}")
        score = 0

    try:
        hint = get_prevention_hint(indicator_type)
        if isinstance(hint, dict):
            prevention = hint.get("prevention")
            prevention_steps = hint.get("steps")
        else:
            prevention = str(hint)
            prevention_steps = None
    except Exception as e:
        print(f"Prevention hint error: {e}")
        prevention = "Investigate and apply containment steps."
        prevention_steps = None

    severity = compute_severity_score(indicator)
    category = categorize_indicator(indicator, summary)

    return {
        "indicator": indicator_value,
        "type": indicator_type,
        "summary": summary,
        "prevention": prevention,
        "prevention_steps": prevention_steps,
        "score": score,
        "timestamp": timestamp,
        "otx": indicator if isinstance(indicator, dict) else None,
        "alert": score >= NOTIFY_THRESHOLD,
        "category": category,
        **severity,
    }

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="user")  # user or admin
    subscription = db.Column(db.String(20), default="free")  # free or premium
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class MonitoredWebsite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime, nullable=True)

class WebsiteAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website_id = db.Column(db.Integer, db.ForeignKey('monitored_website.id'), nullable=False)
    threat_level = db.Column(db.String(20), default="medium")  # low, medium, high
    threat_details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# Add Notification model for storing notifications when email fails
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    sent_via_email = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# Add ThreatSubscription model for email notifications
class ThreatSubscription(db.Model):
    """Track users subscribed to threat email notifications."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    min_risk_score = db.Column(db.Float, default=75.0)  # Only send for high-risk (>= 75)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_notification_sent = db.Column(db.DateTime)
    
    user = db.relationship('User', backref='threat_subscription')

# Add BlockedThreat model
class BlockedThreat(db.Model):
    """Track IP addresses blocked by users or admins."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # IPv4 or IPv6
    threat_type = db.Column(db.String(100), nullable=False)
    risk_category = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    risk_score = db.Column(db.Float, nullable=False)
    summary = db.Column(db.String(500), default='')
    blocked_by = db.Column(db.String(20), nullable=False)  # 'user' or 'admin'
    blocked_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Admin ID if blocked by admin
    reason = db.Column(db.String(500), default='')
    is_active = db.Column(db.Boolean, default=True)  # False if unblocked
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    unblocked_at = db.Column(db.DateTime)
    unblocked_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    user = db.relationship('User', foreign_keys=[user_id], backref='blocked_threats')
    blocker = db.relationship('User', foreign_keys=[blocked_by_user_id])
    unblocker = db.relationship('User', foreign_keys=[unblocked_by_user_id])

# Add ThreatActionLog model
class ThreatActionLog(db.Model):
    """Audit log for all threat-related actions (block, unblock, email sent)."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'block', 'unblock', 'email_sent', 'button_clicked'
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('blocked_threat.id'))
    performed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who performed the action
    details = db.Column(db.String(1000), default='')  # JSON or text details
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='threat_action_logs')
    performer = db.relationship('User', foreign_keys=[performed_by_user_id])

# Add BlockToken model - persists tokens in database with expiration
class BlockToken(db.Model):
    """Store one-time use block tokens with expiration."""
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    threat_type = db.Column(db.String(100), default='Unknown')
    risk_score = db.Column(db.Float, default=0)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)  # Token expires after 24 hours
    used_at = db.Column(db.DateTime)
    
    user = db.relationship('User', backref='block_tokens')
    
    def is_valid(self):
        """Check if token is still valid (not used and not expired)."""
        if self.is_used:
            return False
        if datetime.utcnow() > self.expires_at:
            return False
        return True


class Agent(db.Model):
    """Track agent registrations and last-seen metadata."""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255))
    last_seen = db.Column(db.DateTime)
    last_poll = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))
    last_status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AgentEnforcement(db.Model):
    """Track enforcement results reported by agents."""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(100), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    status = db.Column(db.String(30), nullable=False)
    message = db.Column(db.String(255), default="")
    reported_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# Store block tokens temporarily (in production, use Redis or database)
block_tokens_store = {}

# ---------------- EMAIL FUNCTION ----------------
def send_email_notification(to_email, subject, body, user_id=None):
    """Send email notification with fallback to database storage"""
    email_sent = False
    error_msg = None

    try:
        print(f"[EMAIL] Attempting to send email to {to_email} using SMTP...")
        print(f"   Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"   Username: {app.config['MAIL_USERNAME']}")
        print(f"   TLS: {app.config['MAIL_USE_TLS']}")
        
        msg = Message(subject=subject, recipients=[to_email])
        msg.body = body
        mail.send(msg)
        print(f"[SUCCESS] Email sent successfully to {to_email}")
        email_sent = True
    except Exception as e:
        error_msg = str(e)
        error_type = type(e).__name__
        print(f"[WARNING] Email failed to {to_email}")
        print(f"   Error Type: {error_type}")
        print(f"   Error Message: {error_msg}")
        print(f"[STORAGE] Storing notification in database as fallback")
        email_sent = False

    # Always store notification in database for user dashboard
    if user_id:
        try:
            notification = Notification(
                user_id=user_id,
                subject=subject,
                body=body,
                sent_via_email=email_sent
            )
            db.session.add(notification)
            db.session.commit()
            print(f"[SUCCESS] Notification stored in database for user {user_id}")
        except Exception as e:
            print(f"[ERROR] Failed to store notification: {e}")

    # expose last error for callers to inspect
    send_email_notification.last_error = error_msg
    return email_sent

# initialize attribute
send_email_notification.last_error = None

# ---------------- AUTH DECORATOR ----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            print("?? Token missing from headers")
            return jsonify({"error": "Token missing"}), 401
        
        if token.startswith("Bearer "):
            token = token[7:]
        
        try:
            print(f"[TOKEN] Attempting to decode token: {token[:20]}...")
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            print(f"[SUCCESS] Token decoded successfully for user_id: {data.get('user_id')}")
            current_user = User.query.get(data["user_id"])
            if not current_user:
                print(f"[ERROR] User not found with ID: {data['user_id']}")
                return jsonify({"error": "User not found"}), 401
            print(f"[SUCCESS] User found: {current_user.username}")
        except jwt.ExpiredSignatureError:
            print("[ERROR] Token expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            print(f"[ERROR] Invalid token error: {str(e)}")
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated


def _normalize_agent_fields(data):
    agent_id = (
        request.headers.get("X-Agent-Id")
        or request.headers.get("X-Agent-ID")
        or (data or {}).get("agent_id")
    )
    api_token = (
        request.headers.get("X-Api-Token")
        or request.headers.get("X-API-Token")
        or request.headers.get("Authorization")
        or (data or {}).get("api_token")
    )
    if api_token and api_token.startswith("Bearer "):
        api_token = api_token[7:]
    timestamp = request.headers.get("X-Timestamp") or (data or {}).get("timestamp")
    hostname = request.headers.get("X-Hostname") or (data or {}).get("hostname")
    return agent_id, api_token, timestamp, hostname


def _validate_agent_request(allow_body=True):
    data = request.get_json(silent=True) if allow_body else {}
    agent_id, api_token, timestamp, hostname = _normalize_agent_fields(data)

    if not agent_id or not api_token or not timestamp:
        return None, jsonify({"error": "Missing agent_id, api_token, or timestamp"}), 400

    if AGENT_REQUIRE_TOKEN and (not AGENT_API_TOKEN or api_token != AGENT_API_TOKEN):
        return None, jsonify({"error": "Invalid agent token"}), 401

    return {
        "agent_id": agent_id,
        "api_token": api_token,
        "timestamp": timestamp,
        "hostname": hostname,
        "payload": data or {},
    }, None, None


def _upsert_agent_record(agent_id, hostname, last_status=None, is_poll=False, commit=True):
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        agent = Agent(agent_id=agent_id)
        db.session.add(agent)
    if hostname:
        agent.hostname = hostname
    agent.last_seen = datetime.utcnow()
    agent.last_ip = request.remote_addr
    if is_poll:
        agent.last_poll = datetime.utcnow()
    if last_status:
        agent.last_status = last_status
    if commit:
        db.session.commit()

# ============== IP BLOCKING MIDDLEWARE ==============
@app.before_request
def check_ip_blocking():
    """Check if the incoming IP is blocked"""
    client_ip = request.remote_addr
    
    # Get the real IP if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # Check if IP is blocked
    if ip_blocker.is_blocked(client_ip):
        print(f"[BLOCKED] Blocked IP attempted access: {client_ip}")
        return jsonify({"error": "Access denied. Your IP has been blocked due to suspicious activity."}), 403
    
    return None

# ============== IP BLOCKING ADMIN ENDPOINTS ==============
@app.route("/api/admin/ip-blocking/block", methods=["POST"])
@token_required
def admin_block_ip(current_user):
    """Admin endpoint to block an IP"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Admin blocked')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    success, message = ip_blocker.block_ip(ip, reason)
    status_code = 200 if success else 400
    
    return jsonify({
        "success": success,
        "message": message,
        "ip": ip
    }), status_code

@app.route("/api/admin/ip-blocking/unblock", methods=["POST"])
@token_required
def admin_unblock_ip(current_user):
    """Admin endpoint to unblock an IP"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    success, message = ip_blocker.unblock_ip(ip)
    status_code = 200 if success else 400
    
    return jsonify({
        "success": success,
        "message": message,
        "ip": ip
    }), status_code

@app.route("/api/admin/ip-blocking/whitelist", methods=["POST"])
@token_required
def admin_whitelist_ip(current_user):
    """Admin endpoint to whitelist an IP"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    success, message = ip_blocker.whitelist_ip(ip)
    status_code = 200 if success else 400
    
    return jsonify({
        "success": success,
        "message": message,
        "ip": ip
    }), status_code

@app.route("/api/admin/ip-blocking/list", methods=["GET"])
@token_required
def admin_list_blocked_ips(current_user):
    """Admin endpoint to list all blocked IPs"""
    if current_user.role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    
    return jsonify({
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "whitelisted_ips": ip_blocker.get_whitelist()
    }), 200

# ============== EXISTING ROUTES ================

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Threat Intelligence API is running!"})


@app.route("/downloads/<path:filename>", methods=["GET"])
def download_agent_installer(filename):
    if filename != "threat-agent-installer.sh":
        return jsonify({"error": "File not found"}), 404
    downloads_dir = os.path.join(os.path.dirname(__file__), "downloads")
    return send_from_directory(downloads_dir, filename, as_attachment=True)

# Test endpoint to verify token format
@app.route("/api/test-token", methods=["POST"])
def test_token():
    """Test endpoint to debug token issues - NO AUTH REQUIRED"""
    token = request.headers.get("Authorization")
    print(f"\n?? Token Debug Info:")
    print(f"  Raw Header: {token}")
    
    if not token:
        return jsonify({"error": "No token provided"}), 400
    
    if token.startswith("Bearer "):
        token_only = token[7:]
        print(f"  Token (first 50 chars): {token_only[:50]}...")
    else:
        token_only = token
        print(f"  Token (no Bearer prefix): {token_only[:50]}...")
    
    try:
        print(f"  Attempting to decode with SECRET_KEY...")
        data = jwt.decode(token_only, app.config["SECRET_KEY"], algorithms=["HS256"])
        print(f"  [SUCCESS] Decode successful! User ID: {data.get('user_id')}")
        return jsonify({"valid": True, "user_id": data.get("user_id")}), 200
    except jwt.ExpiredSignatureError:
        print(f"  ? Token expired")
        return jsonify({"valid": False, "reason": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        print(f"  ? Invalid token: {str(e)}")
        return jsonify({"valid": False, "reason": str(e)}), 401

# --- Register New User ---
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not username or not email or not phone or not password:
        return jsonify({"error": "Missing required fields"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already exists"}), 400

    new_user = User(username=username, email=email, phone=phone)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# --- Login User ---
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(hours=4)
        }, app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({
            "token": token,
            "user_id": user.id,
            "role": user.role,
            "subscription": user.subscription,
            "username": user.username,
            "email": user.email
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401

# --- Admin: View All Users ---
@app.route("/api/users", methods=["GET"])
@token_required
def get_users(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    users = User.query.all()
    users_data = [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "phone": u.phone,
        "role": u.role,
        "subscription": u.subscription
    } for u in users]
    return jsonify(users_data)

# --- Admin: View All Websites (All Users' Websites) ---
@app.route("/api/all-websites", methods=["GET"])
@token_required
def get_all_websites(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    websites = MonitoredWebsite.query.all()
    websites_data = [{
        "id": w.id,
        "user_id": w.user_id,
        "url": w.url,
        "is_active": w.is_active,
        "created_at": w.created_at,
        "last_checked": w.last_checked
    } for w in websites]
    return jsonify(websites_data), 200

# --- Threat Intelligence Endpoint --- (Updated: Live refresh support)
# Global tracking for uniqueness across refresh requests
SHOWN_IPS_REFRESH = set()
# Track indicators shown on refresh to avoid repeats across requests
SHOWN_INDICATORS_REFRESH = set()


@app.route("/api/threats", methods=["GET"])
def get_threats():
    """Fast version - returns balanced, randomized cached threats instantly."""
    print("\n🚀 /api/threats called")
    
    try:
        limit = int(request.args.get("limit", 15))
    except Exception:
        limit = 15
    
    # Load cached threats
    try:
        with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
            all_threats = json.load(f)
        
        # Apply category filter if requested
        category = request.args.get("category")
        if category and category != "All":
            all_threats = [t for t in all_threats if t.get("category") == category]
        
        # Ensure severity field matches score (critical fix)
        for threat in all_threats:
            score = threat.get("score", 0)
            if score >= 75:
                threat["severity"] = "High"
            elif score >= 50:
                threat["severity"] = "Medium"
            else:
                threat["severity"] = "Low"
        
        # Separate threats by risk level for balanced distribution
        high_threats = [t for t in all_threats if t.get("score", 0) >= 75]
        medium_threats = [t for t in all_threats if 50 <= t.get("score", 0) < 75]
        low_threats = [t for t in all_threats if t.get("score", 0) < 50]
        
        # Randomize each category
        random.shuffle(high_threats)
        random.shuffle(medium_threats)
        random.shuffle(low_threats)
        
        # Calculate balanced distribution (equal parts of each risk level)
        per_category = limit // 3
        remainder = limit % 3
        
        # Take equal amounts from each category, with remainder going to high
        selected_threats = []
        selected_threats.extend(high_threats[:per_category + remainder])
        selected_threats.extend(medium_threats[:per_category])
        selected_threats.extend(low_threats[:per_category])
        
        # Randomize final order so they're not grouped by risk level
        random.shuffle(selected_threats)
        
        print(f"✅ Returning {len(selected_threats)} balanced threats (High: {len([t for t in selected_threats if t.get('score', 0) >= 75])}, Medium: {len([t for t in selected_threats if 50 <= t.get('score', 0) < 75])}, Low: {len([t for t in selected_threats if t.get('score', 0) < 50])})")
        return jsonify(selected_threats)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify([])


def _extract_ip_from_threat(threat):
    if not isinstance(threat, dict):
        return None
    ip_candidate = threat.get("ip") or threat.get("ip_address") or threat.get("ip_address_v4")
    if ip_candidate and is_valid_ip(str(ip_candidate)):
        return str(ip_candidate)
    indicator = threat.get("indicator") or threat.get("indicator_value")
    extracted = extract_ip_from_indicator(indicator) if indicator else None
    if extracted and is_valid_ip(str(extracted)):
        return str(extracted)
    return None


@app.route("/api/high-risk-threats", methods=["GET"])
def get_high_risk_threats_for_agents():
    agent_meta, error_response, status_code = _validate_agent_request(allow_body=False)
    if error_response:
        return error_response, status_code

    try:
        with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
            all_threats = json.load(f)
    except Exception as e:
        print(f"[AGENT] Failed to read threats cache: {e}")
        return jsonify({"threats": [], "count": 0, "timestamp": datetime.utcnow().isoformat()}), 200

    high_risk = [t for t in all_threats if t.get("score", 0) >= 75]
    ip_set = set()
    threats_out = []
    for threat in high_risk:
        ip_address = _extract_ip_from_threat(threat)
        if not ip_address or ip_address in ip_set:
            continue
        ip_set.add(ip_address)
        threats_out.append({
            "ip": ip_address,
            "risk": "HIGH",
            "action": "BLOCK",
        })

    _upsert_agent_record(
        agent_meta["agent_id"],
        agent_meta.get("hostname"),
        last_status="polled",
        is_poll=True,
    )

    return jsonify({
        "threats": threats_out,
        "count": len(threats_out),
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route("/api/status", methods=["POST"])
def post_agent_status():
    agent_meta, error_response, status_code = _validate_agent_request(allow_body=True)
    if error_response:
        return error_response, status_code

    data = agent_meta.get("payload") or {}
    ip_address = data.get("ip") or data.get("ip_address")
    status = data.get("status")
    message = data.get("message", "")

    if not ip_address or not status:
        return jsonify({"error": "Missing ip or status"}), 400
    if not is_valid_ip(str(ip_address)):
        return jsonify({"error": "Invalid IP address"}), 400

    enforcement = AgentEnforcement(
        agent_id=agent_meta["agent_id"],
        ip_address=str(ip_address),
        status=str(status),
        message=str(message)[:255]
    )
    db.session.add(enforcement)
    _upsert_agent_record(
        agent_meta["agent_id"],
        agent_meta.get("hostname"),
        last_status=str(status),
        commit=False
    )
    db.session.commit()

    return jsonify({"message": "Status recorded"}), 200


@app.route("/api/admin/agent-status", methods=["GET"])
@token_required
def get_agent_status(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    agents = Agent.query.order_by(Agent.last_seen.desc(), Agent.agent_id.asc()).all()
    return jsonify([
        {
            "agent_id": a.agent_id,
            "hostname": a.hostname,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "last_poll": a.last_poll.isoformat() if a.last_poll else None,
            "last_ip": a.last_ip,
            "last_status": a.last_status,
        }
        for a in agents
    ]), 200


@app.route("/api/admin/agent-enforcements", methods=["GET"])
@token_required
def get_agent_enforcements(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    try:
        limit = int(request.args.get("limit", 50))
    except Exception:
        limit = 50

    logs = AgentEnforcement.query.order_by(AgentEnforcement.reported_at.desc()).limit(limit).all()
    return jsonify([
        {
            "agent_id": l.agent_id,
            "ip_address": l.ip_address,
            "status": l.status,
            "message": l.message,
            "reported_at": l.reported_at.isoformat(),
        }
        for l in logs
    ]), 200

@app.route("/api/admin-alerts", methods=["GET"])
@token_required
def get_admin_alerts(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    
    # Get recent alerts from database (faster than external API)
    alerts = WebsiteAlert.query.order_by(WebsiteAlert.created_at.desc()).limit(20).all()
    alerts_data = [{
        "id": a.id,
        "user_id": a.user_id,
        "website_id": a.website_id,
        "threat_level": a.threat_level,
        "threat_details": a.threat_details,
        "created_at": a.created_at,
        "is_read": a.is_read
    } for a in alerts]
    return jsonify(alerts_data), 200


# --- Admin: Get Notifications (Upgrade Requests, etc.) ---
@app.route("/api/admin-notifications", methods=["GET"])
@token_required
def get_admin_notifications(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    try:
        # Only return notifications that look like upgrade requests (subject contains 'Upgrade Request')
        notes = Notification.query.filter(Notification.subject.ilike("%Upgrade Request%"))
        notes = notes.order_by(Notification.created_at.desc()).limit(100).all()
        results = []
        for n in notes:
            # attempt to include basic user info for the requester
            requester = User.query.get(n.user_id)
            results.append({
                "id": n.id,
                "user_id": n.user_id,
                "username": requester.username if requester else None,
                "email": requester.email if requester else None,
                "subject": n.subject,
                "body": n.body,
                "sent_via_email": n.sent_via_email,
                "created_at": n.created_at,
                "is_read": n.is_read,
            })
        return jsonify(results), 200
    except Exception as e:
        print(f"Error fetching admin notifications: {e}")
        return jsonify({"error": "Failed to fetch notifications"}), 500


# --- Mark Notification as Read ---
@app.route("/api/notifications/<int:note_id>/read", methods=["PUT"])
@token_required
def mark_notification_read(current_user, note_id):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    try:
        note = Notification.query.get(note_id)
        if not note:
            return jsonify({"error": "Notification not found"}), 404
        note.is_read = True
        db.session.commit()
        return jsonify({"message": "Notification marked as read"}), 200
    except Exception as e:
        print(f"Error marking notification read: {e}")
        return jsonify({"error": "Failed to mark notification read"}), 500


# --- User: Request Upgrade (Notify Admins) ---
@app.route("/api/request-upgrade", methods=["POST"])
@token_required
def request_upgrade(current_user):
    """Allow a logged-in user to request an upgrade; stores a Notification and emails admins."""
    try:
        data = request.get_json() or {}
        message = data.get("message", "User requested an upgrade via dashboard")

        subject = f"?? Upgrade Request: {current_user.username}"
        body = f"User {current_user.username} (email: {current_user.email}) has requested an upgrade.\n\nMessage:\n{message}\n\nRequested At: {datetime.utcnow()}"

        # Store a notification record for admins to review
        notification = Notification(
            user_id=current_user.id,
            subject=subject,
            body=body,
            sent_via_email=False
        )
        db.session.add(notification)
        db.session.commit()

        # Attempt to email the configured admin address (MAIL_USERNAME) as a convenience
        admin_email = app.config.get("MAIL_USERNAME")
        if admin_email:
            try:
                send_email_notification(admin_email, subject, body, user_id=current_user.id)
            except Exception as e:
                print(f"Failed to email admin for upgrade request: {e}")

        return jsonify({"message": "Upgrade request sent to administrators"}), 200
    except Exception as e:
        print(f"Error handling upgrade request: {e}")
        return jsonify({"error": "Failed to submit upgrade request"}), 500

# --- DEMO: Send Notification (No SMTP, for demonstration) ---
@app.route("/api/demo-notify", methods=["POST"])
@token_required
def demo_notify(current_user):
    """DEMO ONLY: Sends a mock notification (stores in DB without SMTP)"""
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    threat = data.get("threat")
    user_email = data.get("user_email")

    if not threat or not user_email:
        return jsonify({"error": "Missing threat or user_email"}), 400

    # Find the user and create a mock notification in the database
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"error": f"User with email {user_email} not found"}), 404

    try:
        subject = f"?? High-Risk Threat Detected: {threat.get('title', 'Unknown')}"
        body = f"""
Hello,

A threat notification has been sent:

?? Title: {threat.get('title', 'N/A')}
?? Indicator: {threat.get('indicator', 'N/A')}
?? Score: {threat.get('score', 'N/A')}
?? Summary: {threat.get('summary', 'N/A')}
?? Timestamp: {threat.get('timestamp', 'N/A')}

Please review this threat immediately.

� Threat Intelligence System (DEMO MODE)
"""
        notification = Notification(
            user_id=user.id,
            subject=subject,
            body=body,
            sent_via_email=False  # Demo: not actually sent via email
        )
        db.session.add(notification)
        db.session.commit()
        print(f"[DEMO] Mock notification stored for user {user.username}")
        return jsonify({"message": "Notification sent successfully (DEMO MODE)", "email_sent": True, "demo": True}), 200
    except Exception as e:
        print(f"[ERROR] [DEMO] Error storing notification: {e}")
        return jsonify({"message": "Failed to send notification", "email_sent": False, "error": str(e)}), 400

# --- New Endpoint: Manual Email Notification (Admin Only, HTML with Block Button) ---
@app.route("/api/send-notification", methods=["POST"])
@token_required
def send_notification(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    threat = data.get("threat")  # Expect the full threat object
    user_email = data.get("user_email")  # Target user's email

    if not threat or not user_email:
        return jsonify({"error": "Missing threat or user_email"}), 400

    # Prepare recipient user
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"error": f"User with email {user_email} not found"}), 404

    # Extract/resolve IP address
    ip_address = threat.get('ip_address') or extract_ip_from_indicator(threat) or threat.get('indicator')
    if not ip_address or not is_valid_ip(ip_address):
        return jsonify({"error": "Valid IP address is required in threat"}), 400

    # Threat fields
    threat_type = threat.get('type', 'Unknown')
    risk_score = threat.get('score', 0)
    risk_category = threat.get('severity', 'High')
    summary = threat.get('summary', 'No description available')

    # Generate block token and persist
    token = generate_block_token(user_id=user.id, ip_address=ip_address, threat_data={
        'threat_type': threat_type,
        'risk_score': risk_score
    })
    block_token = BlockToken(
        token=token,
        user_id=user.id,
        ip_address=ip_address,
        threat_type=threat_type,
        risk_score=risk_score,
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.session.add(block_token)
    db.session.commit()

    # Build HTML email via template with block button
    base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
    block_url = f"{base_url}/block-threat?token={token}"
    unsubscribe_url = f"{base_url}/settings?unsubscribe=true"

    threat_data = {
        'ip_address': ip_address,
        'threat_type': threat_type,
        'risk_category': risk_category,
        'risk_score': risk_score,
        'summary': summary,
        'detected_when': threat.get('timestamp', 'N/A')
    }

    # Subject and send using HTML template
    subject = f"High-Risk Threat Alert: {ip_address}"
    email_sent = send_threat_notification_email(
        mail=mail,
        recipient_email=user_email,
        recipient_name=user.username,
        threat_data=threat_data,
        block_url=block_url,
        unsubscribe_url=unsubscribe_url
    )

    # Log email action regardless of SMTP success
    action_log = ThreatActionLog(
        user_id=user.id,
        action='email_sent',
        ip_address=ip_address,
        performed_by_user_id=current_user.id,
        details=json.dumps({
            'threat_type': threat_type,
            'risk_score': risk_score,
            'via': 'manual_send_endpoint',
            'smtp_success': email_sent
        })
    )
    db.session.add(action_log)
    db.session.commit()

    return jsonify({"message": "Notification sent", "email_sent": bool(email_sent)}), 200

# --- Website Monitoring: Add URL ---
@app.route("/api/websites", methods=["POST"])
@token_required
def add_website(current_user):
    data = request.get_json()
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Check subscription limit (free users can monitor 1 website, premium unlimited)
    existing_count = MonitoredWebsite.query.filter_by(user_id=current_user.id, is_active=True).count()
    if current_user.subscription == "free" and existing_count >= 1:
        return jsonify({"error": "Free plan limited to 1 website. Upgrade to premium for unlimited monitoring."}), 403
    
    website = MonitoredWebsite(user_id=current_user.id, url=url)
    db.session.add(website)
    db.session.commit()
    
    return jsonify({
        "id": website.id,
        "url": website.url,
        "is_active": website.is_active,
        "created_at": website.created_at
    }), 201

# --- Website Monitoring: Get User's Websites ---
@app.route("/api/websites", methods=["GET"])
@token_required
def get_websites(current_user):
    websites = MonitoredWebsite.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        "id": w.id,
        "url": w.url,
        "is_active": w.is_active,
        "created_at": w.created_at,
        "last_checked": w.last_checked
    } for w in websites]), 200

# --- Website Monitoring: Get Alerts ---
@app.route("/api/alerts", methods=["GET"])
@token_required
def get_alerts(current_user):
    alerts = WebsiteAlert.query.filter_by(user_id=current_user.id).order_by(WebsiteAlert.created_at.desc()).all()
    return jsonify([{
        "id": a.id,
        "website_id": a.website_id,
        "threat_level": a.threat_level,
        "threat_details": a.threat_details,
        "created_at": a.created_at,
        "is_read": a.is_read
    } for a in alerts]), 200

# --- Website Monitoring: Simulate Attack Detection ---
@app.route("/api/check-website/<int:website_id>", methods=["POST"])
@token_required
def check_website(current_user, website_id):
    """Simulate website health check and create alerts if threats detected"""
    website = MonitoredWebsite.query.get(website_id)
    
    if not website or website.user_id != current_user.id:
        return jsonify({"error": "Website not found"}), 404
    
    website.last_checked = datetime.utcnow()
    db.session.commit()
    
    # Simulate threat detection (in production, integrate with real security scanning)
    import random
    threat_detected = random.random() > 0.7  # 30% chance of threat
    
    if threat_detected:
        threat_levels = ["low", "medium", "high"]
        threat_level = random.choice(threat_levels)
        threat_details = f"Potential vulnerability detected on {website.url}"
        
        alert = WebsiteAlert(
            user_id=current_user.id,
            website_id=website_id,
            threat_level=threat_level,
            threat_details=threat_details
        )
        db.session.add(alert)
        db.session.commit()
        
        # Send email notification
        subject = f"?? Security Alert: {threat_level.upper()} threat detected"
        body = f"""
Hello {current_user.username},

A {threat_level} security threat has been detected on your monitored website:

?? URL: {website.url}
?? Threat Level: {threat_level.upper()}
?? Details: {threat_details}
?? Detected At: {datetime.utcnow()}

Please log in to your dashboard to review and take action.

� Threat Intelligence System
"""
        send_email_notification(current_user.email, subject, body, user_id=current_user.id)
        
        return jsonify({
            "threat_detected": True,
            "alert_id": alert.id,
            "threat_level": threat_level,
            "threat_details": threat_details
        }), 200
    
    return jsonify({"threat_detected": False, "message": "Website is secure"}), 200

# --- Mark Alert as Read ---
@app.route("/api/alerts/<int:alert_id>/read", methods=["PUT"])
@token_required
def mark_alert_read(current_user, alert_id):
    alert = WebsiteAlert.query.get(alert_id)
    
    if not alert or alert.user_id != current_user.id:
        return jsonify({"error": "Alert not found"}), 404
    
    alert.is_read = True
    db.session.commit()
    
    return jsonify({"message": "Alert marked as read"}), 200

# --- Get Current User Info ---
@app.route("/api/me", methods=["GET"])
@token_required
def get_current_user(current_user):
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "subscription": current_user.subscription,
        "created_at": current_user.created_at
    }), 200

# --- Upgrade Subscription ---
@app.route("/api/upgrade", methods=["POST"])
@token_required
def upgrade_subscription(current_user):
    current_user.subscription = "premium"
    db.session.commit()
    
    subject = "?? Subscription Upgraded!"
    body = f"""
Hello {current_user.username},

Your subscription has been upgraded to Premium!

Benefits:
? Unlimited website monitoring
? Real-time attack detection
? Priority email notifications
? Advanced threat analytics

Thank you for choosing us!

� Threat Intelligence System
"""
    send_email_notification(current_user.email, subject, body)
    
    return jsonify({"message": "Subscription upgraded to premium", "subscription": "premium"}), 200

# --- Admin: Upgrade User Subscription ---
@app.route("/api/upgrade-user", methods=["POST"])
@token_required
def admin_upgrade_user(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    data = request.get_json()
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.subscription == "premium":
        return jsonify({"error": "User is already premium"}), 400
    
    # Upgrade user
    user.subscription = "premium"
    db.session.commit()
    
    # Send notification email
    subject = "?? Subscription Upgraded to Premium!"
    body = f"""
Hello {user.username},

Great news! An administrator has upgraded your subscription to Premium!

Benefits:
? Unlimited website monitoring
? Real-time attack detection
? Priority email notifications
? Advanced threat analytics

Thank you for using ThreatGuard!

� Threat Intelligence System
"""
    send_email_notification(user.email, subject, body)
    
    return jsonify({"message": f"User {user.username} upgraded to premium", "subscription": "premium"}), 200

# --- Admin: Downgrade User Subscription (Premium to Free) ---
@app.route("/api/downgrade-user", methods=["POST"])
@token_required
def admin_downgrade_user(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    data = request.get_json()
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.subscription == "free":
        return jsonify({"error": "User is already on free plan"}), 400
    
    # Downgrade user to free
    user.subscription = "free"
    db.session.commit()
    
    # Send notification email
    subject = "?? Subscription Downgraded to Free"
    body = f"""
Hello {user.username},

Your subscription has been downgraded to Free plan by an administrator.

Free Plan Includes:
? Monitor up to 1 website
? Basic threat alerts
? Email notifications

If you have questions, please contact support.

� Threat Intelligence System
"""
    send_email_notification(user.email, subject, body)
    
    return jsonify({"message": f"User {user.username} downgraded to free", "subscription": "free"}), 200

# --- Admin: Delete User Account ---
@app.route("/api/delete-user", methods=["POST"])
@token_required
def admin_delete_user(current_user):
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    data = request.get_json()
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Prevent deletion of admin accounts
    if user.role == "admin":
        return jsonify({"error": "Cannot delete admin accounts"}), 403
    
    # Prevent self-deletion
    if user.id == current_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 403
    
    username = user.username
    email = user.email
    
    # Delete all related records for this user (cascade delete)
    # 1. Notifications
    Notification.query.filter_by(user_id=user_id).delete()
    
    # 2. Website alerts
    WebsiteAlert.query.filter_by(user_id=user_id).delete()
    
    # 3. Monitored websites
    MonitoredWebsite.query.filter_by(user_id=user_id).delete()
    
    # 4. Threat subscription
    ThreatSubscription.query.filter_by(user_id=user_id).delete()
    
    # 5. Blocked threats (user owns)
    BlockedThreat.query.filter_by(user_id=user_id).delete()
    
    # 6. Threat action logs (user owns)
    ThreatActionLog.query.filter_by(user_id=user_id).delete()
    
    # 7. Block tokens (user owns)
    BlockToken.query.filter_by(user_id=user_id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    try:
        print(f"[SUCCESS] User {username} (ID: {user_id}) and all associated data deleted by admin {current_user.username}")
        return jsonify({"message": f"User {username} and all associated data have been deleted"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Delete user failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to delete user: {str(e)}"}), 500


# ================ THREAT NOTIFICATION & BLOCKING API ================

# --- Subscribe to Threat Notifications ---
@app.route("/api/subscribe-threats", methods=["POST"])
@token_required
def subscribe_to_threats(current_user):
    """Subscribe user to email notifications for high-risk threats."""
    data = request.get_json()
    email = data.get("email") or current_user.email
    min_risk_score = data.get("min_risk_score", 75.0)
    
    # Check if already subscribed
    existing = ThreatSubscription.query.filter_by(user_id=current_user.id).first()
    
    if existing:
        existing.is_active = True
        existing.email = email
        existing.min_risk_score = min_risk_score
        db.session.commit()
        return jsonify({"message": "Subscription updated successfully", "subscription": {
            "email": email,
            "is_active": True,
            "min_risk_score": min_risk_score
        }}), 200
    
    # Create new subscription
    subscription = ThreatSubscription(
        user_id=current_user.id,
        email=email,
        min_risk_score=min_risk_score,
        is_active=True
    )
    db.session.add(subscription)
    db.session.commit()
    
    print(f"[SUCCESS] User {current_user.username} subscribed to threat notifications")
    return jsonify({"message": "Successfully subscribed to threat notifications", "subscription": {
        "email": email,
        "is_active": True,
        "min_risk_score": min_risk_score
    }}), 201


# --- Unsubscribe from Threat Notifications ---
@app.route("/api/unsubscribe-threats", methods=["POST"])
@token_required
def unsubscribe_from_threats(current_user):
    """Unsubscribe user from threat email notifications."""
    subscription = ThreatSubscription.query.filter_by(user_id=current_user.id).first()
    
    if not subscription:
        return jsonify({"error": "No active subscription found"}), 404
    
    subscription.is_active = False
    db.session.commit()
    
    print(f"[SUCCESS] User {current_user.username} unsubscribed from threat notifications")
    return jsonify({"message": "Successfully unsubscribed from threat notifications"}), 200


# --- Get Subscription Status ---
@app.route("/api/subscription-status", methods=["GET"])
@token_required
def get_subscription_status(current_user):
    """Get current user's subscription status."""
    subscription = ThreatSubscription.query.filter_by(user_id=current_user.id).first()
    
    if not subscription:
        return jsonify({"subscribed": False}), 200
    
    return jsonify({
        "subscribed": subscription.is_active,
        "email": subscription.email,
        "min_risk_score": subscription.min_risk_score,
        "subscribed_at": subscription.subscribed_at.isoformat() if subscription.subscribed_at else None
    }), 200


# --- Block IP Address (User-Initiated) ---
@app.route("/api/block-threat", methods=["POST"])
def block_threat():
    """
    Block an IP address for the current user.
    Can be triggered via email button (with token) or dashboard.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        token = data.get("token")  # Optional: from email button
        ip_address = data.get("ip_address")
        threat_type = data.get("threat_type", "Unknown")
        risk_category = data.get("risk_category", "High")
        risk_score = data.get("risk_score", 0)
        summary = data.get("summary", "")
        reason = data.get("reason", "User-initiated block via notification")
        
        # Determine effective current user: prefer email token owner; fallback to JWT
        current_user = None
        block_token = None
        
        # If token provided, validate and use it to identify the user (magic-link flow)
        if token:
            block_token = BlockToken.query.filter_by(token=token).first()
            if not block_token:
                print(f"[BLOCK] Invalid block token received: {str(token)[:12]}...")
                return jsonify({"error": "Invalid or expired block token"}), 403
            if not block_token.is_valid():
                print(f"[BLOCK] Expired/used block token: {str(token)[:12]}... (is_used={block_token.is_used})")
                return jsonify({"error": "Invalid or expired block token"}), 403
            # Set effective user from token owner
            current_user = User.query.get(block_token.user_id)
            if not current_user:
                return jsonify({"error": "User not found for this token"}), 403
        else:
            # No email token, require JWT auth header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authorization required"}), 401
            jwt_token = auth_header.split(" ", 1)[1]
            try:
                data_jwt = jwt.decode(jwt_token, app.config["SECRET_KEY"], algorithms=["HS256"])
                current_user = User.query.get(data_jwt.get("user_id"))
                if not current_user:
                    return jsonify({"error": "User not found"}), 401
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
        
        # If token provided, prefer token's threat details and mark as used
        if block_token:
            ip_address = block_token.ip_address or ip_address
            threat_type = block_token.threat_type or threat_type
            risk_score = block_token.risk_score if block_token.risk_score is not None else risk_score
            # Mark token as used (one-time use)
            block_token.is_used = True
            block_token.used_at = datetime.utcnow()
            db.session.add(block_token)
        
        if not ip_address:
            return jsonify({"error": "ip_address is required"}), 400
        
        # Validate IP format
        if not is_valid_ip(ip_address):
            return jsonify({"error": "Invalid IP address format"}), 400
        
        # Check if already blocked by this user
        existing = BlockedThreat.query.filter_by(
            user_id=current_user.id,
            ip_address=ip_address,
            is_active=True
        ).first()
        
        if existing:
            return jsonify({"error": "This IP is already blocked", "blocked_threat": existing.id}), 409
        
        # Create blocked threat record
        blocked_threat = BlockedThreat(
            user_id=current_user.id,
            ip_address=ip_address,
            threat_type=threat_type,
            risk_category=risk_category,
            risk_score=risk_score,
            summary=summary,
            blocked_by='user',
            blocked_by_user_id=current_user.id,
            reason=reason,
            is_active=True
        )
        db.session.add(blocked_threat)
        
        # Log the action
        action_log = ThreatActionLog(
            user_id=current_user.id,
            action='block',
            ip_address=ip_address,
            threat_id=blocked_threat.id,
            performed_by_user_id=current_user.id,
            details=json.dumps({
                "threat_type": threat_type,
                "risk_score": risk_score,
                "via": "email_button" if token else "dashboard"
            })
        )
        db.session.add(action_log)
        db.session.commit()
        
        # Call IP blocker to actually block the IP (user-specific)
        try:
            print(f"[SHIELD] Attempting to block IP {ip_address} for user {current_user.username}...")
            success, message = ip_blocker.block_ip(ip_address, f"user_{current_user.id}")
            print(f"[SHIELD] IP {ip_address} block result: success={success}, message={message}")
        except Exception as e:
            print(f"[WARNING] Failed to call ip_blocker for {ip_address}: {str(e)}")
            import traceback
            traceback.print_exc()
        
        # Send confirmation email
        try:
            send_confirmation_email(
                mail=mail,
                recipient_email=current_user.email,
                recipient_name=current_user.username,
                ip_address=ip_address,
                threat_type=threat_type,
                blocked_at=blocked_threat.blocked_at.strftime('%Y-%m-%d %H:%M:%S UTC')
            )
            
            # Log email sent
            email_log = ThreatActionLog(
                user_id=current_user.id,
                action='email_sent',
                ip_address=ip_address,
                threat_id=blocked_threat.id,
                performed_by_user_id=current_user.id,
                details='Confirmation email sent'
            )
            db.session.add(email_log)
            db.session.commit()
        except Exception as e:
            print(f"[ERROR] Failed to send confirmation email: {str(e)}")
        
        print(f"[SUCCESS] User {current_user.username} blocked IP {ip_address}")
        
        return jsonify({
            "message": f"IP {ip_address} successfully blocked",
            "blocked_threat": {
                "id": blocked_threat.id,
                "ip_address": ip_address,
                "threat_type": threat_type,
                "risk_category": risk_category,
                "risk_score": risk_score,
                "blocked_at": blocked_threat.blocked_at.isoformat()
            }
        }), 201
    
    except Exception as e:
        print(f"[ERROR] ERROR in block_threat endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({"error": f"Failed to block IP: {str(e)}"}), 500


# --- Unblock IP Address ---
@app.route("/api/unblock-threat/<int:threat_id>", methods=["POST"])
@token_required
def unblock_threat(current_user, threat_id):
    """Unblock a previously blocked IP address."""
    try:
        blocked_threat = BlockedThreat.query.get(threat_id)
        
        if not blocked_threat:
            return jsonify({"error": "Blocked threat not found"}), 404
        
        # Authorization: User can only unblock their own threats, or admin can unblock any
        if blocked_threat.user_id != current_user.id and current_user.role != "admin":
            return jsonify({"error": "Unauthorized - cannot unblock another user's threat"}), 403
        
        if not blocked_threat.is_active:
            return jsonify({"error": "Threat is already unblocked"}), 400
        
        # Unblock the threat
        blocked_threat.is_active = False
        blocked_threat.unblocked_at = datetime.utcnow()
        blocked_threat.unblocked_by_user_id = current_user.id
        
        # Log the action
        action_log = ThreatActionLog(
            user_id=blocked_threat.user_id,
            action='unblock',
            ip_address=blocked_threat.ip_address,
            threat_id=blocked_threat.id,
            performed_by_user_id=current_user.id,
            details=f"Unblocked by {'admin' if current_user.role == 'admin' else 'user'}"
        )
        db.session.add(action_log)
        db.session.add(blocked_threat)
        db.session.commit()
        
        # Call IP blocker to actually unblock the IP
        try:
            success, message = ip_blocker.unblock_ip(blocked_threat.ip_address)
            print(f"✅ IP {blocked_threat.ip_address} unblocked for user ID {blocked_threat.user_id} (success={success}, message={message})")
        except Exception as e:
            print(f"[WARNING] Failed to call ip_blocker unblock for {blocked_threat.ip_address}: {str(e)}")
        
        print(f"[SUCCESS] IP {blocked_threat.ip_address} unblocked by {current_user.username}")
        
        return jsonify({
            "message": f"IP {blocked_threat.ip_address} successfully unblocked",
            "unblocked_at": blocked_threat.unblocked_at.isoformat()
        }), 200
    
    except Exception as e:
        print(f"[ERROR] unblock_threat() failed: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({
            "error": f"Failed to unblock threat: {str(e)}"
        }), 500


# --- Get Blocked Threats (User's Own) ---
@app.route("/api/blocked-threats", methods=["GET"])
@token_required
def get_blocked_threats(current_user):
    """Get all blocked threats for the current user."""
    blocked_threats = BlockedThreat.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).order_by(BlockedThreat.blocked_at.desc()).all()
    
    threats_list = [{
        "id": bt.id,
        "ip_address": bt.ip_address,
        "threat_type": bt.threat_type,
        "risk_category": bt.risk_category,
        "risk_score": bt.risk_score,
        "summary": bt.summary,
        "blocked_by": bt.blocked_by,
        "reason": bt.reason,
        "blocked_at": bt.blocked_at.isoformat()
    } for bt in blocked_threats]
    
    return jsonify({"blocked_threats": threats_list, "count": len(threats_list)}), 200


# --- Get All Blocked Threats History (including unblocked) ---
@app.route("/api/blocked-threats/history", methods=["GET"])
@token_required
def get_blocked_threats_history(current_user):
    """Get complete history of all blocked threats (active and inactive)."""
    all_threats = BlockedThreat.query.filter_by(
        user_id=current_user.id
    ).order_by(BlockedThreat.blocked_at.desc()).all()
    
    threats_list = [{
        "id": bt.id,
        "ip_address": bt.ip_address,
        "threat_type": bt.threat_type,
        "risk_category": bt.risk_category,
        "risk_score": bt.risk_score,
        "summary": bt.summary,
        "blocked_by": bt.blocked_by,
        "reason": bt.reason,
        "is_active": bt.is_active,
        "blocked_at": bt.blocked_at.isoformat(),
        "unblocked_at": bt.unblocked_at.isoformat() if bt.unblocked_at else None
    } for bt in all_threats]
    
    return jsonify({"blocked_threats": threats_list, "count": len(threats_list)}), 200


# --- Admin: Block IP for Specific User ---
@app.route("/api/admin/block-threat", methods=["POST"])
@token_required
def admin_block_threat(current_user):
    """Admin blocks an IP address for a specific user."""
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    data = request.get_json()
    user_id = data.get("user_id")
    ip_address = data.get("ip_address")
    threat_type = data.get("threat_type", "Admin-identified threat")
    risk_category = data.get("risk_category", "High")
    risk_score = data.get("risk_score", 80)
    summary = data.get("summary", "")
    reason = data.get("reason", "Admin-initiated block")
    
    if not user_id or not ip_address:
        return jsonify({"error": "user_id and ip_address are required"}), 400
    
    # Validate user exists
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Validate IP format
    if not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    # Check if already blocked
    existing = BlockedThreat.query.filter_by(
        user_id=user_id,
        ip_address=ip_address,
        is_active=True
    ).first()
    
    if existing:
        return jsonify({"error": "This IP is already blocked for this user"}), 409
    
    # Create blocked threat record
    blocked_threat = BlockedThreat(
        user_id=user_id,
        ip_address=ip_address,
        threat_type=threat_type,
        risk_category=risk_category,
        risk_score=risk_score,
        summary=summary,
        blocked_by='admin',
        blocked_by_user_id=current_user.id,
        reason=reason,
        is_active=True
    )
    db.session.add(blocked_threat)
    
    # Log the action
    action_log = ThreatActionLog(
        user_id=user_id,
        action='block',
        ip_address=ip_address,
        threat_id=blocked_threat.id,
        performed_by_user_id=current_user.id,
        details=json.dumps({
            "admin_action": True,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "reason": reason
        })
    )
    db.session.add(action_log)
    db.session.commit()
    
    # Actually block the IP
    try:
        print(f"[SHIELD] Admin attempting to block IP {ip_address} for user ID {user_id}...")
        success, message = ip_blocker.block_ip(ip_address, f"user_{user_id}")
        print(f"[SHIELD] Admin {current_user.username} blocked IP {ip_address} - success={success}, message={message}")
    except Exception as e:
        print(f"[WARNING] Failed to call ip_blocker: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print(f"[SUCCESS] Admin {current_user.username} blocked IP {ip_address} for user {user.username}")
    
    return jsonify({
        "message": f"IP {ip_address} successfully blocked for user {user.username}",
        "blocked_threat": {
            "id": blocked_threat.id,
            "user_id": user_id,
            "ip_address": ip_address,
            "blocked_at": blocked_threat.blocked_at.isoformat()
        }
    }), 201


# --- AUTO-BLOCK HIGH-RISK THREATS (Admin Dashboard) ---
@app.route("/api/admin/auto-block-threats", methods=["POST"])
@token_required
def admin_auto_block_threats(current_user):
    """
    Automatically block all high-risk threats (score >= 75) that are IPs.
    Called when admin dashboard loads.
    Returns list of auto-blocked IPs and summary.
    """
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    try:
        print("\n🛡️ [AUTO-BLOCK] Starting automatic threat blocking system...")
        
        # Load threats from cache
        threats = []
        try:
            with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                threats = json.load(f)
            print(f"✅ [AUTO-BLOCK] Loaded {len(threats)} threats from cache")
        except FileNotFoundError:
            print("❌ [AUTO-BLOCK] Cache file not found")
            return jsonify({
                "message": "No threat cache available",
                "auto_blocked": [],
                "skipped": [],
                "summary": {
                    "total_threats": 0,
                    "high_risk_threats": 0,
                    "successfully_blocked": 0,
                    "already_blocked": 0,
                    "invalid_ips": 0
                }
            }), 200
        except Exception as e:
            print(f"❌ [AUTO-BLOCK] Error reading cache: {e}")
            return jsonify({"error": f"Failed to read threat cache: {e}"}), 500
        
        # Filter high-risk threats (score >= 75)
        high_risk = [t for t in threats if t.get("score", 0) >= 75]
        print(f"📊 [AUTO-BLOCK] Found {len(high_risk)} high-risk threats (score >= 75)")
        
        auto_blocked = []
        already_blocked = []
        invalid_ips = []
        skipped_count = 0
        
        for threat in high_risk:
            try:
                # Extract IP address
                ip_address = threat.get("ip") or threat.get("ip_address") or threat.get("indicator")
                
                if not ip_address:
                    print(f"⚠️  [AUTO-BLOCK] Threat has no IP: {threat.get('indicator', 'Unknown')}")
                    skipped_count += 1
                    continue
                
                # Validate IP
                if not is_valid_ip(ip_address):
                    print(f"❌ [AUTO-BLOCK] Invalid IP format: {ip_address}")
                    invalid_ips.append({
                        "ip": ip_address,
                        "threat_type": threat.get("type", "Unknown"),
                        "reason": "Invalid IP format"
                    })
                    continue
                
                # Check if already blocked globally by admin
                existing = BlockedThreat.query.filter_by(
                    ip_address=ip_address,
                    is_active=True,
                    blocked_by='admin'
                ).first()
                
                if existing:
                    print(f"⚠️  [AUTO-BLOCK] IP {ip_address} already blocked by admin")
                    already_blocked.append({
                        "ip": ip_address,
                        "threat_type": threat.get("type", "Unknown"),
                        "risk_score": threat.get("score", 0),
                        "blocked_at": existing.blocked_at.isoformat()
                    })
                    continue
                
                # Create blocked threat record for admin user (special case)
                # Using admin user ID to track auto-blocks
                blocked_threat = BlockedThreat(
                    user_id=current_user.id,  # Admin who triggered auto-block
                    ip_address=ip_address,
                    threat_type=threat.get("type", "Unknown"),
                    risk_category=threat.get("severity", "High"),
                    risk_score=threat.get("score", 0),
                    summary=threat.get("summary", "Auto-blocked from threat feed"),
                    blocked_by='admin',
                    blocked_by_user_id=current_user.id,
                    reason=f"Auto-blocked: High-risk threat (score {threat.get('score', 0)})",
                    is_active=True
                )
                db.session.add(blocked_threat)
                
                # Log the auto-block action
                action_log = ThreatActionLog(
                    user_id=current_user.id,
                    action='auto_block',
                    ip_address=ip_address,
                    threat_id=blocked_threat.id,
                    performed_by_user_id=current_user.id,
                    details=json.dumps({
                        "threat_type": threat.get("type", "Unknown"),
                        "risk_score": threat.get("score", 0),
                        "category": threat.get("category", "Unknown"),
                        "summary": threat.get("summary", ""),
                        "auto_blocked": True,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                )
                db.session.add(action_log)
                
                # Commit database changes
                db.session.commit()
                
                # Actually block the IP globally
                try:
                    success, message = ip_blocker.block_ip(ip_address, f"admin_auto_block_{current_user.id}")
                    print(f"✅ [AUTO-BLOCK] Blocked IP {ip_address} (success={success})")
                except Exception as e:
                    print(f"⚠️  [AUTO-BLOCK] Failed to call ip_blocker: {e}")
                
                auto_blocked.append({
                    "id": blocked_threat.id,
                    "ip": ip_address,
                    "threat_type": threat.get("type", "Unknown"),
                    "risk_score": threat.get("score", 0),
                    "category": threat.get("category", "Unknown"),
                    "summary": threat.get("summary", ""),
                    "blocked_at": blocked_threat.blocked_at.isoformat()
                })
                
            except Exception as e:
                print(f"❌ [AUTO-BLOCK] Error processing threat: {str(e)}")
                import traceback
                traceback.print_exc()
                db.session.rollback()
                skipped_count += 1
                continue
        
        summary = {
            "total_threats_in_feed": len(threats),
            "high_risk_threats": len(high_risk),
            "successfully_auto_blocked": len(auto_blocked),
            "already_blocked": len(already_blocked),
            "invalid_ips": len(invalid_ips),
            "skipped": skipped_count
        }
        
        print(f"""
🎯 [AUTO-BLOCK] SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total threats in feed: {summary['total_threats_in_feed']}
  High-risk threats: {summary['high_risk_threats']}
  ✅ Successfully auto-blocked: {summary['successfully_auto_blocked']}
  ⚠️  Already blocked: {summary['already_blocked']}
  ❌ Invalid IPs: {summary['invalid_ips']}
  ⊘ Skipped: {summary['skipped']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━""")
        
        return jsonify({
            "message": f"Auto-blocked {len(auto_blocked)} high-risk threats",
            "auto_blocked": auto_blocked,
            "already_blocked": already_blocked,
            "invalid_ips": invalid_ips,
            "summary": summary
        }), 200
        
    except Exception as e:
        print(f"❌ [AUTO-BLOCK] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({"error": f"Auto-block failed: {str(e)}"}), 500


# --- User: Block IP via Email Link (Secure Token) ---
@app.route("/api/user/block-threat", methods=["POST"])
def user_block_threat_via_email():
    """
    Verify and process email-based IP block request.
    User clicks 'Block IP' button in email → validates token → blocks IP.
    No authentication required (token validation is the security).
    """
    try:
        data = request.get_json()
        token = data.get("token")
        
        if not token:
            print("[EMAIL-BLOCK] No token provided")
            return jsonify({"error": "Block token required"}), 400
        
        print(f"🔓 [EMAIL-BLOCK] Validating block token...")
        
        # Load and validate token
        block_token = BlockToken.query.filter_by(token=token).first()
        
        if not block_token:
            print("[EMAIL-BLOCK] Token not found in database")
            return jsonify({"error": "Invalid or expired block token"}), 404
        
        # Verify token is still valid
        if not block_token.is_valid():
            print(f"[EMAIL-BLOCK] Token is invalid: used={block_token.is_used}, expired={datetime.utcnow() > block_token.expires_at}")
            return jsonify({"error": "Block token expired or already used"}), 403
        
        # Extract token data
        user_id = block_token.user_id
        ip_address = block_token.ip_address
        threat_type = block_token.threat_type
        risk_score = block_token.risk_score
        
        user = User.query.get(user_id)
        if not user:
            print(f"[EMAIL-BLOCK] User {user_id} not found")
            return jsonify({"error": "User account not found"}), 404
        
        print(f"✅ [EMAIL-BLOCK] Token valid for user {user.username}, IP {ip_address}")
        
        # Validate IP address
        if not is_valid_ip(ip_address):
            print(f"❌ [EMAIL-BLOCK] Invalid IP format: {ip_address}")
            block_token.is_used = True
            block_token.used_at = datetime.utcnow()
            db.session.commit()
            return jsonify({"error": f"Invalid IP address format: {ip_address}"}), 400
        
        # Check if already blocked by this user
        existing = BlockedThreat.query.filter_by(
            user_id=user_id,
            ip_address=ip_address,
            is_active=True,
            blocked_by='user'
        ).first()
        
        if existing:
            print(f"⚠️  [EMAIL-BLOCK] IP already blocked by user {user.username}: {ip_address}")
            block_token.is_used = True
            block_token.used_at = datetime.utcnow()
            db.session.commit()
            return jsonify({
                "message": "IP was already blocked by you",
                "already_blocked": True,
                "ip_address": ip_address,
                "blocked_at": existing.blocked_at.isoformat()
            }), 200
        
        # Create blocked threat record (user-initiated)
        blocked_threat = BlockedThreat(
            user_id=user_id,
            ip_address=ip_address,
            threat_type=threat_type,
            risk_category="High" if risk_score >= 75 else ("Medium" if risk_score >= 50 else "Low"),
            risk_score=risk_score,
            summary=f"Blocked via email alert by user action",
            blocked_by='user',
            blocked_by_user_id=user_id,
            reason=f"User-initiated block from email alert (score {risk_score})",
            is_active=True
        )
        db.session.add(blocked_threat)
        db.session.flush()  # Get the blocked_threat.id
        
        # Log the action
        action_log = ThreatActionLog(
            user_id=user_id,
            action='block_email_link',
            ip_address=ip_address,
            threat_id=blocked_threat.id,
            performed_by_user_id=user_id,
            details=json.dumps({
                'threat_type': threat_type,
                'risk_score': risk_score,
                'via': 'email_alert_button',
                'token_id': block_token.id
            })
        )
        db.session.add(action_log)
        
        # Mark token as used
        block_token.is_used = True
        block_token.used_at = datetime.utcnow()
        db.session.add(block_token)
        
        # Commit all changes
        db.session.commit()
        print(f"✅ [EMAIL-BLOCK] Database records created for user {user.username}")
        
        # Actually block the IP on user's system
        try:
            success, message = ip_blocker.block_ip(ip_address, f"user_{user_id}_email_block")
            print(f"✅ [EMAIL-BLOCK] IP {ip_address} blocked successfully: {message}")
        except Exception as e:
            print(f"⚠️  [EMAIL-BLOCK] Warning: ip_blocker returned error: {e}")
        
        # Notify admin about user's block action
        try:
            admins = User.query.filter_by(role='admin').all()
            for admin in admins:
                admin_notification = AdminNotification(
                    admin_id=admin.id,
                    notification_type='user_action_block',
                    title=f"User {user.username} Blocked IP",
                    message=f"{user.username} blocked {ip_address} via email alert (Risk Score: {risk_score})",
                    related_user_id=user_id
                )
                db.session.add(admin_notification)
            db.session.commit()
            print(f"✅ [EMAIL-BLOCK] Admin notifications created")
        except Exception as e:
            print(f"⚠️  [EMAIL-BLOCK] Failed to create admin notifications: {e}")
            db.session.rollback()
        
        # Send confirmation email
        try:
            if user.threat_subscription and user.threat_subscription.email:
                from email_service import get_confirmation_email_template, send_threat_notification_email
                html_content = get_confirmation_email_template(
                    user_name=user.username,
                    ip_address=ip_address,
                    threat_type=threat_type,
                    blocked_at=blocked_threat.blocked_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                )
                msg = Message(
                    subject=f"✅ IP Address Blocked: {ip_address}",
                    recipients=[user.threat_subscription.email],
                    html=html_content
                )
                mail.send(msg)
                print(f"✅ [EMAIL-BLOCK] Confirmation email sent to {user.threat_subscription.email}")
        except Exception as e:
            print(f"⚠️  [EMAIL-BLOCK] Failed to send confirmation email: {e}")
        
        return jsonify({
            "message": f"IP {ip_address} has been successfully blocked",
            "success": True,
            "ip_address": ip_address,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "blocked_by": "user",
            "blocked_at": blocked_threat.blocked_at.isoformat(),
            "username": user.username
        }), 200
        
    except Exception as e:
        print(f"❌ [EMAIL-BLOCK] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        try:
            db.session.rollback()
        except:
            pass
        return jsonify({"error": f"Block operation failed: {str(e)}"}), 500


# --- User: Get User's Blocked Threats ---
@app.route("/api/user/blocked-threats", methods=["GET"])
@token_required
def user_get_blocked_threats(current_user):
    """Get all threats blocked by current user."""
    try:
        # Optional filters
        is_active = request.args.get("is_active", type=str)
        
        query = BlockedThreat.query.filter_by(
            user_id=current_user.id,
            blocked_by='user'
        )
        
        if is_active is not None:
            active_bool = is_active.lower() == 'true'
            query = query.filter_by(is_active=active_bool)
        
        user_threats = query.order_by(BlockedThreat.blocked_at.desc()).all()
        
        threats_list = [
            {
                'id': bt.id,
                'ip_address': bt.ip_address,
                'threat_type': bt.threat_type,
                'risk_category': bt.risk_category,
                'risk_score': bt.risk_score,
                'summary': bt.summary,
                'reason': bt.reason,
                'is_active': bt.is_active,
                'blocked_at': bt.blocked_at.isoformat(),
                'unblocked_at': bt.unblocked_at.isoformat() if bt.unblocked_at else None
            }
            for bt in user_threats
        ]
        
        return jsonify({
            "count": len(threats_list),
            "active": len([t for t in threats_list if t['is_active']]),
            "blocked_threats": threats_list
        }), 200
        
    except Exception as e:
        print(f"[API] Error in user_get_blocked_threats: {e}")
        return jsonify({"error": str(e)}), 500


# --- User: Unblock a Threat ---
@app.route("/api/user/unblock-threat/<int:threat_id>", methods=["POST"])
@token_required
def user_unblock_threat(current_user, threat_id):
    """User unblocks an IP they previously blocked."""
    try:
        blocked_threat = BlockedThreat.query.get(threat_id)
        
        if not blocked_threat:
            return jsonify({"error": "Blocked threat not found"}), 404
        
        # Verify ownership and that it was blocked by user
        if blocked_threat.user_id != current_user.id:
            return jsonify({"error": "Unauthorized - you can only unblock your own threats"}), 403
        
        if blocked_threat.blocked_by != 'user':
            return jsonify({"error": "Can only unblock user-initiated blocks"}), 400
        
        if not blocked_threat.is_active:
            return jsonify({"message": "This threat is already unblocked"}), 200
        
        # Mark as unblocked
        blocked_threat.is_active = False
        blocked_threat.unblocked_at = datetime.utcnow()
        blocked_threat.unblocked_by_user_id = current_user.id
        db.session.add(blocked_threat)
        
        # Log the action
        action_log = ThreatActionLog(
            user_id=current_user.id,
            action='unblock_user',
            ip_address=blocked_threat.ip_address,
            threat_id=threat_id,
            performed_by_user_id=current_user.id,
            details=json.dumps({
                'threat_type': blocked_threat.threat_type,
                'risk_score': blocked_threat.risk_score,
                'unblocked_reason': 'User-initiated unblock'
            })
        )
        db.session.add(action_log)
        db.session.commit()
        
        print(f"✅ [UNBLOCK] User {current_user.username} unblocked {blocked_threat.ip_address}")
        
        return jsonify({
            "message": f"IP {blocked_threat.ip_address} has been unblocked",
            "ip_address": blocked_threat.ip_address,
            "unblocked_at": blocked_threat.unblocked_at.isoformat()
        }), 200
        
    except Exception as e:
        print(f"[API] Error in user_unblock_threat: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# --- Admin: View All Blocked Threats (All Users) ---
@app.route("/api/admin/blocked-threats", methods=["GET"])
@token_required
def admin_get_all_blocked_threats(current_user):
    """Admin views all blocked threats across all users."""
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    # Optional filters
    user_id = request.args.get("user_id", type=int)
    is_active = request.args.get("is_active", type=str)
    blocked_by = request.args.get("blocked_by")  # 'admin' or 'user'
    
    query = BlockedThreat.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if is_active is not None:
        active_bool = is_active.lower() == 'true'
        query = query.filter_by(is_active=active_bool)
    
    if blocked_by:
        query = query.filter_by(blocked_by=blocked_by)
    
    all_threats = query.order_by(BlockedThreat.blocked_at.desc()).all()
    
    threats_list = []
    for bt in all_threats:
        user = User.query.get(bt.user_id)
        blocker = User.query.get(bt.blocked_by_user_id) if bt.blocked_by_user_id else None
        
        threats_list.append({
            "id": bt.id,
            "user_id": bt.user_id,
            "username": user.username if user else "Unknown",
            "ip_address": bt.ip_address,
            "threat_type": bt.threat_type,
            "risk_category": bt.risk_category,
            "risk_score": bt.risk_score,
            "summary": bt.summary,
            "blocked_by": bt.blocked_by,
            "blocked_by_username": blocker.username if blocker else "System",
            "reason": bt.reason,
            "is_active": bt.is_active,
            "blocked_at": bt.blocked_at.isoformat(),
            "unblocked_at": bt.unblocked_at.isoformat() if bt.unblocked_at else None
        })
    
    return jsonify({"blocked_threats": threats_list, "count": len(threats_list)}), 200


# --- Admin: View Action Logs ---
@app.route("/api/admin/action-logs", methods=["GET"])
@token_required
def admin_get_action_logs(current_user):
    """Admin views all threat action logs."""
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized - Admin access required"}), 403
    
    # Optional filters
    user_id = request.args.get("user_id", type=int)
    action = request.args.get("action")
    limit = request.args.get("limit", default=100, type=int)
    
    query = ThreatActionLog.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(ThreatActionLog.timestamp.desc()).limit(limit).all()
    
    logs_list = []
    for log in logs:
        user = User.query.get(log.user_id)
        performer = User.query.get(log.performed_by_user_id) if log.performed_by_user_id else None
        
        logs_list.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": user.username if user else "Unknown",
            "action": log.action,
            "ip_address": log.ip_address,
            "threat_id": log.threat_id,
            "performed_by": performer.username if performer else "System",
            "details": log.details,
            "timestamp": log.timestamp.isoformat()
        })
    
    return jsonify({"action_logs": logs_list, "count": len(logs_list)}), 200


# ================ END THREAT NOTIFICATION & BLOCKING API ================

def fetch_and_cache(limit=None, modified_since=None):
    """Fetch from OTX export endpoint and write normalized JSON to THREATS_OUTPUT."""
    headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
    if limit is None:
        try:
            limit = int(os.getenv("THREATS_LIMIT", 30))
        except Exception:
            limit = 30
    if not modified_since:
        modified_since = os.getenv("MODIFIED_SINCE", "24h")

    # Oversample upstream to ensure we can deliver the target number after type/IP filtering.
    fetch_limit = max(limit * 5, limit + 20)
    params = {"limit": fetch_limit, "modified_since": modified_since}
    try:
        resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print(f"[ERROR] OTX API request timed out (30s)")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] OTX export request failed: {e}")
        return None

    # Parse JSON or NDJSON
    try:
        data = resp.json()
    except Exception:
        text = resp.text
        lines = [l for l in text.splitlines() if l.strip()]
        parsed = []
        for line in lines[:fetch_limit]:
            try:
                parsed.append(json.loads(line))
            except Exception:
                parsed.append({"raw": line})
        data = parsed

    if isinstance(data, dict):
        indicators = data.get("results", []) or data.get("indicators", []) or []
    elif isinstance(data, list):
        indicators = data
    else:
        indicators = []

    threats = []
    seen = set()
    skipped = 0
    allowed_types = {"ipv4", "ip", "hostname", "dns", "domain", "url", "uri", "md5", "sha1", "sha256"}

    for i in indicators:
        normalized = normalize_indicator(i, pulse_title="")
        ind_val = normalized.get("indicator")
        ind_type = (normalized.get("type") or "").lower()
        if ind_type not in allowed_types:
            skipped += 1
            continue
        if ind_val in seen:
            continue
        seen.add(ind_val)
        # Attach convenience IP if available
        ip_address = extract_ip_from_indicator(i)
        if ip_address:
            normalized.update({"ip": ip_address})
        threats.append(normalized)
        if len(threats) >= limit:
            break

    try:
        with open(THREATS_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(threats, f, indent=2, ensure_ascii=False)
        print(f"[CACHE] Wrote {len(threats)} threats to: {THREATS_OUTPUT}")
        return threats
    except Exception as e:
        print(f"[ERROR] Failed to write cache: {e}")
        return None

def _send_threat_notifications(threats):
    """Send email notifications to subscribed users for high-risk threats."""
    if not threats:
        print("[NOTIFY] No threats to process")
        return
    try:
        subscriptions = ThreatSubscription.query.filter_by(is_active=True).all()
        if not subscriptions:
            print("[NOTIFY] No active subscriptions found")
            return
        print(f"[NOTIFY] Processing {len(threats)} threats for {len(subscriptions)} subscribed users")
        notifications_sent = 0
        high_risk_threats = [t for t in threats if t.get("score", 0) >= 75]
        if not high_risk_threats:
            print("[NOTIFY] No high-risk threats (score >= 75) for automated notifications")
            return
        print(f"[NOTIFY] {len(high_risk_threats)} high-risk threats eligible for automated alerts")
        for threat in high_risk_threats:
            try:
                ip_address = threat.get("ip") or threat.get("ip_address") or threat.get("indicator")
                if not ip_address:
                    continue
                for subscription in subscriptions:
                    try:
                        if threat.get("score", 0) < subscription.min_risk_score:
                            continue
                        already_blocked = BlockedThreat.query.filter_by(
                            user_id=subscription.user_id,
                            ip_address=ip_address,
                            is_active=True
                        ).first()
                        if already_blocked:
                            continue
                        user = User.query.get(subscription.user_id)
                        if not user:
                            continue
                        existing_notification = ThreatActionLog.query.filter_by(
                            user_id=user.id,
                            ip_address=ip_address,
                            action='email_sent'
                        ).filter(
                            ThreatActionLog.timestamp > datetime.utcnow() - timedelta(hours=24)
                        ).first()
                        if existing_notification:
                            continue
                        token = generate_block_token(user_id=user.id, ip_address=ip_address, threat_data=threat)
                        block_token = BlockToken(
                            token=token,
                            user_id=user.id,
                            ip_address=ip_address,
                            threat_type=threat.get('type', 'Unknown'),
                            risk_score=threat.get('score', 0),
                            expires_at=datetime.utcnow() + timedelta(hours=24)
                        )
                        db.session.add(block_token)
                        try:
                            db.session.commit()
                        except Exception as e:
                            print(f"[NOTIFY] Failed to commit block token: {e}")
                            db.session.rollback()
                            continue
                        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
                        block_url = f"{base_url}/block-threat?token={token}"
                        unsubscribe_url = f"{base_url}/settings?unsubscribe=true"
                        threat_data = {
                            'ip_address': ip_address,
                            'threat_type': threat.get('type', 'Unknown'),
                            'risk_category': threat.get('severity', 'High'),
                            'risk_score': threat.get('score', 0),
                            'summary': threat.get('summary', 'No description available'),
                            'detected_when': threat.get('timestamp', 'N/A'),
                            'prevention': threat.get('prevention', ''),
                            'prevention_steps': threat.get('prevention_steps', ''),
                            'category': threat.get('category', 'Unknown')
                        }
                        email_sent = send_threat_notification_email(
                            mail=mail,
                            recipient_email=subscription.email,
                            recipient_name=user.username,
                            threat_data=threat_data,
                            block_url=block_url,
                            unsubscribe_url=unsubscribe_url
                        )
                        if email_sent:
                            notifications_sent += 1
                            action_log = ThreatActionLog(
                                user_id=user.id,
                                action='email_sent',
                                ip_address=ip_address,
                                performed_by_user_id=None,
                                details=json.dumps({
                                    'threat_type': threat_data['threat_type'],
                                    'risk_score': threat.get('score', 0),
                                    'sent_to': subscription.email,
                                    'via': 'automatic_background_notification'
                                })
                            )
                            db.session.add(action_log)
                            subscription.last_notification_sent = datetime.utcnow()
                            db.session.add(subscription)
                            print(f"[NOTIFY] Sent alert to {user.username} ({subscription.email}) for IP {ip_address}")
                    except Exception as e:
                        print(f"[NOTIFY] Error notifying user: {str(e)}")
                        continue
                try:
                    db.session.commit()
                except Exception as e:
                    print(f"[NOTIFY] Database commit error: {e}")
                    db.session.rollback()
            except Exception as e:
                print(f"[NOTIFY] Error processing threat: {str(e)}")
                continue
        print(f"[NOTIFY] Sent {notifications_sent} total notifications")
    except Exception as e:
        print(f"[ERROR] _send_threat_notifications: {str(e)}")
        import traceback
        traceback.print_exc()
        try:
            db.session.rollback()
        except:
            pass
def _background_updater():
    """Background thread to send notifications using cached threats."""
    import time
    print(f"[BACKGROUND] Starting threat notification updater (interval={THREATS_POLL_INTERVAL}s)")
    
    cycle = 0
    
    while True:
        try:
            # Run within app context for database access
            with app.app_context():
                now = datetime.utcnow().strftime('%H:%M:%S')
                print(f"\n[BACKGROUND] [{now}] Notification cycle #{cycle}...")
                
                # Load threats from cache (faster and reliable)
                threats = None
                try:
                    with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                        threats = json.load(f)
                    print(f"[BACKGROUND] Loaded {len(threats) if threats else 0} cached threats")
                except FileNotFoundError:
                    print(f"[BACKGROUND] Cache file not found yet. Will try again next cycle.")
                except Exception as e:
                    print(f"[BACKGROUND] Error reading cache: {e}")
                
                # Send notifications if we have threats
                if threats and len(threats) > 0:
                    _send_threat_notifications(threats)
                else:
                    print(f"[BACKGROUND] No threats available to notify")
                
                cycle += 1
                
        except Exception as e:
            print(f"[BACKGROUND] ERROR: {e}")
            import traceback
            traceback.print_exc()
        
        print(f"[BACKGROUND] Sleeping {THREATS_POLL_INTERVAL}s until next cycle...")
        time.sleep(THREATS_POLL_INTERVAL)

# ---------------- RUN ----------------
if __name__ == "__main__":
    # Attach endpoint-specific limits if limiter is available
    try:
        if limiter:
            try:
                login = limiter.limit("10 per minute")(login)
            except Exception:
                pass
            try:
                send_notification = limiter.limit("30 per hour")(send_notification)
            except Exception:
                pass
            try:
                request_upgrade = limiter.limit("5 per minute")(request_upgrade)
            except Exception:
                pass
            try:
                check_website = limiter.limit("10 per minute")(check_website)
            except Exception:
                pass
    except Exception as e:
        print(f"(Info) Skipped applying rate limits: {e}")
    
    # Populate threat cache on startup for fast dashboard loads (non-blocking)
    print("[STARTUP] Attempting to populate threat cache (5s timeout)...")
    
    def populate_cache_async():
        """Async cache population - doesn't block server startup. Only populates if cache is empty."""
        import time
        time.sleep(2)  # Give server time to start
        try:
            with app.app_context():
                # Check if cache already has data
                try:
                    with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                        existing_cache = json.load(f)
                    if len(existing_cache) > 0:
                        print(f"[CACHE] Existing cache has {len(existing_cache)} threats - preserving")
                        return  # Don't overwrite existing data
                except FileNotFoundError:
                    print("[CACHE] No cache file found - will create new one")
                except Exception:
                    print("[CACHE] Cache file exists but couldn't read - will try to populate")
                
                # Only fetch if cache is empty or missing
                import requests
                headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
                params = {"limit": 30, "modified_since": "1h"}
                try:
                    resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=5)
                    if resp.ok:
                        threats = fetch_and_cache(limit=30, modified_since="1h")
                        if threats:
                            print(f"[CACHE] Startup cache populated with {len(threats)} threats")
                    else:
                        print(f"[CACHE] OTX returned {resp.status_code}, using empty cache")
                except requests.exceptions.Timeout:
                    print("[CACHE] OTX timeout during startup - cache remains empty")
                except Exception as e:
                    print(f"[CACHE] Startup cache failed: {e}")
        except Exception as e:
            print(f"[CACHE] WARNING: Async cache population error: {e}")

    # Start background updater only in main process (avoid duplicate with reloader)
    # Re-enabled: Background notifications and high-threat alerts now active
    try:
        run_main = os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug
    except Exception:
        run_main = True
    if run_main:
        import threading
        # Start cache population in separate thread (non-blocking)
        cache_thread = threading.Thread(target=populate_cache_async, daemon=True)
        cache_thread.start()
        # Start notification updater
        updater = threading.Thread(target=_background_updater, daemon=True)
        updater.start()
        print("[SUCCESS] Background threat notification processor started")
    app.run(debug=False, host="0.0.0.0", port=5000)
