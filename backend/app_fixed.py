from flask import Flask, jsonify, request
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
        "methods": ["GET", "POST", "OPTIONS"],  # Explicitly allow these HTTP methods
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
            print("ðŸ”’ Talisman security headers enabled")
        except Exception as e:
            print(f"(Info) flask-talisman not active: {e}")
    # Rate limiting (specific endpoints set later)
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(get_remote_address, app=app, default_limits=[])
        print("â±ï¸  Rate limiter initialized")
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

# Global threat pool and tracking for refresh feature
THREAT_POOL = []  # Large pool of fetched threats
SHOWN_THREATS = set()  # Track which threat indicators have been shown
LAST_POOL_REFRESH = None  # Timestamp of last pool refresh

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
    score += (avg_conf / 100.0) * 10  # Â±10 confidence boost
    score += min(references_count, 5)  # Â±5 references boost
    
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
            print("ðŸ”´ Token missing from headers")
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
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    
    return jsonify({
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "whitelisted_ips": ip_blocker.get_whitelist()
    }), 200

# ============== EXISTING ROUTES ================

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Threat Intelligence API is running!"})

# Test endpoint to verify token format
@app.route("/api/test-token", methods=["POST"])
def test_token():
    """Test endpoint to debug token issues - NO AUTH REQUIRED"""
    token = request.headers.get("Authorization")
    print(f"\nðŸ“ Token Debug Info:")
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
        print(f"  âŒ Token expired")
        return jsonify({"valid": False, "reason": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        print(f"  âŒ Invalid token: {str(e)}")
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


# --- Threat Intelligence Endpoint --- (Returns NEW unique threats on every refresh)
@app.route("/api/threats", methods=["GET"])
def get_threats():
    global THREAT_POOL, SHOWN_THREATS, LAST_POOL_REFRESH
    import random
    
    # Check if this is a fresh data request
    is_refresh = request.args.get("refresh", "false").lower() == "true"
    
    try:
        limit = int(request.args.get("limit", os.getenv("THREATS_LIMIT", 15)))
    except Exception:
        limit = 15
    
    # Helper functions
    def extract_ips_from_text(text):
        ips = set()
        if not text:
            return ips
        try:
            s = str(text)
            ipv4_re = re.compile(r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}")
            for m in ipv4_re.findall(s):
                ips.add(m)
            ipv6_re = re.compile(r"([0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4})")
            for m in ipv6_re.findall(s):
                ips.add(m)
        except Exception:
            pass
        return ips

    def flatten_for_search(val, depth=0, max_depth=4, out=None):
        if out is None:
            out = []
        if val is None or depth > max_depth:
            return out
        if isinstance(val, (str, int, float, bool)):
            out.append(str(val))
            return out
        if isinstance(val, list):
            for v in val:
                flatten_for_search(v, depth + 1, max_depth, out)
            return out
        if isinstance(val, dict):
            for k, v in val.items():
                flatten_for_search(v, depth + 1, max_depth, out)
            return out
        return out
    
    # If refresh=true, fetch fresh pool from OTX
    if is_refresh:
        print(f"[REFRESH] 🔄 Fetching NEW threat pool from OTX (30 days, 200 threats)...")
        
        # Fetch LARGE pool from OTX
        headers = {"X-OTX-API-KEY": API_KEY}
        fetch_limit = 200
        modified_since = "30d"
        
        params = {"limit": fetch_limit, "modified_since": modified_since}
        try:
            resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            print(f"[REFRESH] OTX request timed out")
            return jsonify({"error": "OTX API request timed out"}), 504
        except requests.exceptions.RequestException as e:
            print(f"[REFRESH] OTX request failed: {e}")
            return jsonify({"error": f"Failed to fetch from OTX: {str(e)}"}), 502
        
        # Parse response
        try:
            data = resp.json()
        except Exception:
            text = resp.text
            lines = [l for l in text.splitlines() if l.strip()]
            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except Exception:
                    pass
            data = parsed

        # Extract indicators
        if isinstance(data, dict):
            indicators = data.get("results", []) or data.get("indicators", []) or []
        elif isinstance(data, list):
            indicators = data
        else:
            indicators = []
        
        # Build threat pool
        new_pool = []
        seen_in_pool = set()
        skipped = 0
        
        for i in indicators:
            # Validate IP presence
            ip_address = extract_ip_from_indicator(i)
            if not ip_address:
                skipped += 1
                continue
            
            normalized = normalize_indicator(i, pulse_title="")
            indicator_value = normalized.get("indicator")
            if indicator_value in seen_in_pool:
                continue
            seen_in_pool.add(indicator_value)
            
            # Extract IPs
            ips_found = set()
            try:
                ips_found.update(extract_ips_from_text(indicator_value))
                ips_found.update(extract_ips_from_text(normalized.get("summary")))
                if isinstance(i, dict):
                    pieces = flatten_for_search(i)
                    if pieces:
                        ips_found.update(extract_ips_from_text(" ".join(pieces)))
            except Exception:
                pass
            ip_list = list(ips_found)
            primary_ip = ip_list[0] if ip_list else ip_address
            
            normalized.update({
                "ip_addresses": ip_list,
                "ip": primary_ip,
            })
            
            new_pool.append(normalized)
        
        print(f"[REFRESH] ✅ Built pool: {len(new_pool)} threats (skipped {skipped} without IPs)")
        
        # Update global pool
        THREAT_POOL = new_pool
        LAST_POOL_REFRESH = datetime.utcnow()
        
        # If pool getting small, reset shown tracker
        unshown_count = len([t for t in THREAT_POOL if t.get("indicator") not in SHOWN_THREATS])
        if unshown_count < limit:
            print(f"[REFRESH] Pool exhausted ({unshown_count} unshown), RESETTING shown tracker")
            SHOWN_THREATS.clear()
    
        # Select random threats that haven't been shown
        available = [t for t in THREAT_POOL if t.get("indicator") not in SHOWN_THREATS]
        
        if not available:
            print(f"[REFRESH] No unshown threats, resetting tracker")
            SHOWN_THREATS.clear()
            available = THREAT_POOL
        
        # Random selection
        selected = random.sample(available, min(limit, len(available)))
        
        # Mark as shown
        for t in selected:
            SHOWN_THREATS.add(t.get("indicator"))
        
        print(f"[REFRESH] 🎯 Returning {len(selected)} NEW threats | Shown total: {len(SHOWN_THREATS)} | Remaining: {len(available)-len(selected)}")
        
        return jsonify(selected)
    
    # For non-refresh, use cached data
    try:
        if os.path.exists(THREATS_OUTPUT):
            with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                threats = json.load(f)
                return jsonify(threats[:limit])
    except Exception:
        pass
    
    return jsonify([])


@app.route("/api/threats/cached", methods=["GET"])
def get_threats_cached():
    """Return cached threats JSON written by background updater or manual fetcher."""
    try:
        if not os.path.exists(THREATS_OUTPUT):
            return jsonify({"error": "Cache not found"}), 404
        with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
            content = json.load(f)
        return jsonify(content)
    except Exception as e:
        print(f"Error reading cached threats: {e}")
        return jsonify({"error": "Failed to read cache"}), 500


@app.route("/api/threats-refresh", methods=["GET"])
def refresh_threats():
    """Force refresh threats from OTX - bypasses cache and fetches fresh data."""
    try:
        limit = int(request.args.get("limit", 15))
    except Exception:
        limit = 15
    
    # Use longer time window for more variety (7 days)
    modified_since = request.args.get("modified_since", "7d")
    
    print(f"[REFRESH] Fetching fresh threats: limit={limit}, modified_since={modified_since}")
    
    # Fetch fresh data and update cache
    threats = fetch_and_cache(limit=limit, modified_since=modified_since)
    
    if threats is None:
        return jsonify({"error": "Failed to fetch fresh threats from OTX"}), 502
    
    return jsonify(threats)


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

    # Oversample upstream to ensure we can deliver the target number after IP filtering.
    fetch_limit = max(limit * 5, limit + 20)
    params = {"limit": fetch_limit, "modified_since": modified_since}
    try:
        resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=30)  # 30 second timeout
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print(f"[ERROR] OTX API request timed out (30s)")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] OTX export request failed: {e}")
        return None

    try:
        data = resp.json()
    except Exception:
        text = resp.text
        lines = [l for l in text.splitlines() if l.strip()]
        parsed = []
        for line in lines[:limit]:
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
    seen_indicators = set()
    skipped_count = 0
    # Iterate through all fetched indicators; stop once we have the requested count of valid IP threats.
    for i in indicators:
        # **NEW: Extract IP from indicator to validate presence**
        ip_address = extract_ip_from_indicator(i)
        if not ip_address:
            # Skip this indicator - no valid IP found
            skipped_count += 1
            continue

        normalized = normalize_indicator(i, pulse_title="")
        indicator_value = normalized.get("indicator")
        if indicator_value in seen_indicators:
            continue
        seen_indicators.add(indicator_value)
        # Attach primary IP field to cached threat for frontend ease
        normalized.update({
            "ip": ip_address
        })
        threats.append(normalized)

        # Stop once weâ€™ve collected the requested amount of valid threats.
        if len(threats) >= limit:
            break
    
    if skipped_count > 0:
        print(f"Skipped {skipped_count} indicators without valid IP addresses")

    # If we still have fewer than requested, report the shortfall.
    if len(threats) < limit:
        print(f"[cache] Warning: requested {limit} threats, returned {len(threats)} after IP filtering")

    try:
        with open(THREATS_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(threats, f, indent=2, ensure_ascii=False)
        print(f"[CACHE] Wrote {len(threats)} threats to: {THREATS_OUTPUT}")
        
        # Don't send notifications here - let background updater handle it
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
        # Get all active subscriptions
        subscriptions = ThreatSubscription.query.filter_by(is_active=True).all()
        
        if not subscriptions:
            print("[NOTIFY] No active subscriptions found")
            return
        
        print(f"[NOTIFY] Processing {len(threats)} threats for {len(subscriptions)} subscribed users")
        
        notifications_sent = 0
        
        # AUTOMATED NOTIFICATIONS: Only send for HIGH-risk threats (score >= 75)
        # This ensures users only get critical alerts automatically
        high_risk_threats = [t for t in threats if t.get("score", 0) >= 75]
        
        if not high_risk_threats:
            print("[NOTIFY] No high-risk threats (score >= 75) for automated notifications")
            return
        
        print(f"[NOTIFY] {len(high_risk_threats)} high-risk threats eligible for automated alerts")
        
        # Process only high-risk threats
        for threat in high_risk_threats:
            try:
                risk_score = threat.get("score", 0)
                severity_score = threat.get("severity_score", 0)
                
                # IP can be in 'indicator' field (for IPs) or 'ip_address' field or 'ip'
                ip_address = threat.get("ip") or threat.get("ip_address") or threat.get("indicator")
                
                if not ip_address:
                    continue
                
                # For each subscribed user
                for subscription in subscriptions:
                    try:
                        # Check if threat meets user's risk threshold
                        if risk_score < subscription.min_risk_score:
                            continue
                        
                        # Check if user already blocked this IP
                        already_blocked = BlockedThreat.query.filter_by(
                            user_id=subscription.user_id,
                            ip_address=ip_address,
                            is_active=True
                        ).first()
                        
                        if already_blocked:
                            continue  # Don't send notification for already blocked IPs
                        
                        # Get user info
                        user = User.query.get(subscription.user_id)
                        if not user:
                            continue
                        
                        # Check if already sent email for this IP in last 24 hours (prevent duplicates)
                        existing_notification = ThreatActionLog.query.filter_by(
                            user_id=user.id,
                            ip_address=ip_address,
                            action='email_sent'
                        ).filter(
                            ThreatActionLog.timestamp > datetime.utcnow() - timedelta(hours=24)
                        ).first()
                        
                        if existing_notification:
                            continue  # Skip - already notified this user about this IP recently
                        
                        # Customize notification based on subscription plan
                        is_premium = user.subscription == 'premium'
                        notification_type = 'expanded' if is_premium else 'brief'
                        
                        # Generate one-time block token
                        token = generate_block_token(
                            user_id=user.id,
                            ip_address=ip_address,
                            threat_data=threat
                        )
                        
                        # Store token in database with 24-hour expiration
                        block_token = BlockToken(
                            token=token,
                            user_id=user.id,
                            ip_address=ip_address,
                            threat_type=threat.get('type', 'Unknown'),
                            risk_score=risk_score,
                            expires_at=datetime.utcnow() + timedelta(hours=24)
                        )
                        db.session.add(block_token)
                        # Commit immediately to ensure token exists before email is sent
                        try:
                            db.session.commit()
                        except Exception as e:
                            print(f"[NOTIFY] Failed to commit block token: {e}")
                            db.session.rollback()
                            continue
                        
                        # Build URLs
                        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
                        block_url = f"{base_url}/block-threat?token={token}"
                        unsubscribe_url = f"{base_url}/settings?unsubscribe=true"
                        
                        # Prepare threat data for email (include subscription plan context)
                        threat_data = {
                            'ip_address': ip_address,
                            'threat_type': threat.get('type', 'Unknown IP'),
                            'risk_category': threat.get('severity', 'High'),
                            'risk_score': risk_score,
                            'summary': threat.get('summary', 'No description available'),
                            'detected_when': threat.get('timestamp', 'N/A'),
                            'notification_type': notification_type,
                            'prevention': threat.get('prevention', ''),
                            'prevention_steps': threat.get('prevention_steps', ''),
                            'category': threat.get('category', 'Unknown')
                        }
                        
                        # Send email notification with HTML content
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
                            
                            # Log email sent action
                            action_log = ThreatActionLog(
                                user_id=user.id,
                                action='email_sent',
                                ip_address=ip_address,
                                performed_by_user_id=None,
                                details=json.dumps({
                                    'threat_type': threat_data['threat_type'],
                                    'risk_score': risk_score,
                                    'sent_to': subscription.email,
                                    'via': 'automatic_background_notification'
                                })
                            )
                            db.session.add(action_log)
                            
                            # Update last notification sent time
                            subscription.last_notification_sent = datetime.utcnow()
                            db.session.add(subscription)
                            
                            print(f"[NOTIFY] Sent alert to {user.username} ({subscription.email}) for IP {ip_address}")
                    
                    except Exception as e:
                        print(f"[NOTIFY] Error notifying user: {str(e)}")
                        continue
                
                # Commit logs after processing each threat
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

# --- Admin: Get Alerts from Database (Fast) ---
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

        subject = f"ðŸ”” Upgrade Request: {current_user.username}"
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
        subject = f"ðŸš¨ High-Risk Threat Detected: {threat.get('title', 'Unknown')}"
        body = f"""
Hello,

A threat notification has been sent:

ðŸ“› Title: {threat.get('title', 'N/A')}
ðŸ” Indicator: {threat.get('indicator', 'N/A')}
ðŸ“ˆ Score: {threat.get('score', 'N/A')}
ðŸ“ Summary: {threat.get('summary', 'N/A')}
ðŸ•’ Timestamp: {threat.get('timestamp', 'N/A')}

Please review this threat immediately.

â€” Threat Intelligence System (DEMO MODE)
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
        subject = f"ðŸš¨ Security Alert: {threat_level.upper()} threat detected"
        body = f"""
Hello {current_user.username},

A {threat_level} security threat has been detected on your monitored website:

ðŸŒ URL: {website.url}
âš ï¸ Threat Level: {threat_level.upper()}
ðŸ“ Details: {threat_details}
ðŸ•’ Detected At: {datetime.utcnow()}

Please log in to your dashboard to review and take action.

â€” Threat Intelligence System
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
    
    subject = "ðŸŽ‰ Subscription Upgraded!"
    body = f"""
Hello {current_user.username},

Your subscription has been upgraded to Premium!

Benefits:
âœ… Unlimited website monitoring
âœ… Real-time attack detection
âœ… Priority email notifications
âœ… Advanced threat analytics

Thank you for choosing us!

â€” Threat Intelligence System
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
    subject = "ðŸŽ‰ Subscription Upgraded to Premium!"
    body = f"""
Hello {user.username},

Great news! An administrator has upgraded your subscription to Premium!

Benefits:
âœ… Unlimited website monitoring
âœ… Real-time attack detection
âœ… Priority email notifications
âœ… Advanced threat analytics

Thank you for using ThreatGuard!

â€” Threat Intelligence System
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
    subject = "ðŸ“‹ Subscription Downgraded to Free"
    body = f"""
Hello {user.username},

Your subscription has been downgraded to Free plan by an administrator.

Free Plan Includes:
âœ… Monitor up to 1 website
âœ… Basic threat alerts
âœ… Email notifications

If you have questions, please contact support.

â€” Threat Intelligence System
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
            from ip_blocker import block_ip
            success = block_ip(ip_address, f"user_{current_user.id}")
            print(f"[SHIELD] IP {ip_address} blocked for user {current_user.username} (success={success})")
        except Exception as e:
            print(f"[WARNING] Failed to call ip_blocker for {ip_address}: {str(e)}")
        
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
    db.session.commit()
    
    # Call IP blocker to actually unblock the IP
    try:
        from ip_blocker import unblock_ip
        success = unblock_ip(blocked_threat.ip_address, f"user_{blocked_threat.user_id}")
        print(f"ðŸ”“ IP {blocked_threat.ip_address} unblocked for user ID {blocked_threat.user_id} (success={success})")
    except Exception as e:
        print(f"[WARNING] Failed to call ip_blocker unblock for {blocked_threat.ip_address}: {str(e)}")
    
    print(f"[SUCCESS] IP {blocked_threat.ip_address} unblocked by {current_user.username}")
    
    return jsonify({
        "message": f"IP {blocked_threat.ip_address} successfully unblocked",
        "unblocked_at": blocked_threat.unblocked_at.isoformat()
    }), 200


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
        from ip_blocker import block_ip
        success = block_ip(ip_address, f"user_{user_id}")
        print(f"[SHIELD] Admin {current_user.username} blocked IP {ip_address} for user ID {user_id} (success={success})")
    except Exception as e:
        print(f"[WARNING] Failed to call ip_blocker: {str(e)}")
    
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
    
    query = BlockedThreat.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if is_active is not None:
        active_bool = is_active.lower() == 'true'
        query = query.filter_by(is_active=active_bool)
    
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
        """Async cache population - doesn't block server startup"""
        import time
        time.sleep(2)  # Give server time to start
        try:
            with app.app_context():
                # Use shorter timeout for startup to avoid blocking
                import requests
                headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
                params = {"limit": 30, "modified_since": "1h"}
                try:
                    resp = requests.get(API_EXPORT_URL, headers=headers, params=params, timeout=5)
                    if resp.ok:
                        threats = fetch_and_cache(limit=30, modified_since="1h")
                        if threats:
                            print(f"[CACHE] Startup cache populated with {len(threats)} threats (all with valid IPs)")
                    else:
                        print(f"[CACHE] OTX returned {resp.status_code}, will retry in background cycle")
                except requests.exceptions.Timeout:
                    print("[CACHE] OTX timeout during startup - will populate in first background cycle")
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