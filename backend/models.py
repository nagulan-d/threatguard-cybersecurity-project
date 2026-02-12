from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="user")  # user or admin
    subscription = db.Column(db.String(20), default="free")  # free or premium
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role == "admin"
    
    @property
    def is_premium(self):
        """Check if user has premium subscription"""
        return self.subscription == "premium"

class AccessRequest(db.Model):
    """Track upgrade and feature access requests from users."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)  # 'upgrade', 'feature_access', 'custom_report'
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    details = db.Column(db.String(500), default='')  # User's request details
    admin_notes = db.Column(db.String(500), default='')  # Admin's response
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'request_type': self.request_type,
            'status': self.status,
            'details': self.details,
            'admin_notes': self.admin_notes,
            'created_at': self.created_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }


class AdminNotification(db.Model):
    """Track notifications for admins (latest 10 per admin)."""
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # 'upgrade_request', 'feature_request', 'system_alert'
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    related_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # The user who triggered the notification
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'notification_type': self.notification_type,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat(),
        }


class ThreatIndicator(db.Model):
    """Track processed threat indicators to prevent duplicates."""
    id = db.Column(db.Integer, primary_key=True)
    indicator_value = db.Column(db.String(500), unique=True, nullable=False, index=True)
    indicator_type = db.Column(db.String(50), nullable=False)  # 'ip', 'domain', 'hash', 'url', etc.
    category = db.Column(db.String(50), nullable=False)  # 'Phishing', 'Ransomware', etc.
    severity = db.Column(db.String(20), nullable=False)  # 'Low', 'Medium', 'High'
    score = db.Column(db.Float, default=0.0)  # 0-100 risk score
    summary = db.Column(db.String(500), default='')
    pulse_count = db.Column(db.Integer, default=0)
    reputation = db.Column(db.Float, default=0.0)  # 0-1.0
    last_activity = db.Column(db.DateTime)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    otx_id = db.Column(db.String(100), unique=True)  # AlienVault OTX ID for dedup
    
    def to_dict(self):
        return {
            'id': self.id,
            'indicator': self.indicator_value,
            'type': self.indicator_type,
            'category': self.category,
            'severity': self.severity,
            'score': self.score,
            'summary': self.summary,
            'pulse_count': self.pulse_count,
            'reputation': self.reputation,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
        }


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
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'email': self.email,
            'is_active': self.is_active,
            'min_risk_score': self.min_risk_score,
            'subscribed_at': self.subscribed_at.isoformat(),
            'last_notification_sent': self.last_notification_sent.isoformat() if self.last_notification_sent else None,
        }


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
    
    # No unique constraint - allow re-blocking same IP after unblocking
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'threat_type': self.threat_type,
            'risk_category': self.risk_category,
            'risk_score': self.risk_score,
            'summary': self.summary,
            'blocked_by': self.blocked_by,
            'blocked_by_user_id': self.blocked_by_user_id,
            'reason': self.reason,
            'is_active': self.is_active,
            'blocked_at': self.blocked_at.isoformat(),
            'unblocked_at': self.unblocked_at.isoformat() if self.unblocked_at else None,
        }


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
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'ip_address': self.ip_address,
            'threat_id': self.threat_id,
            'performed_by_user_id': self.performed_by_user_id,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
        }


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
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'threat_type': self.threat_type,
            'risk_score': self.risk_score,
            'is_used': self.is_used,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
        }