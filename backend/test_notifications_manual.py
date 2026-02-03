#!/usr/bin/env python
"""Manually test threat notification sending with sample data."""

from app import app, db, ThreatSubscription, ThreatActionLog, mail
from email_service import send_threat_notification_email, generate_block_token
from datetime import datetime
import secrets
import json

app.app_context().push()

# Sample threat data (matching the structure from OTX API)
sample_threats = [
    {
        "indicator": "192.168.1.100",
        "type": "IPv4",
        "summary": "192.168.1.100 (IPv4) – Suspicious malware command and control server detected",
        "score": 85,
        "severity": "High",
        "severity_score": 85.5,
        "category": "Malware"
    },
    {
        "indicator": "10.0.0.50",
        "type": "IPv4",
        "summary": "10.0.0.50 (IPv4) – Known phishing infrastructure",
        "score": 75,
        "severity": "High",
        "severity_score": 78.2,
        "category": "Phishing"
    },
    {
        "indicator": "172.16.0.1",
        "type": "IPv4",
        "summary": "172.16.0.1 (IPv4) – DDoS attack origin point",
        "score": 88,
        "severity": "High",
        "severity_score": 88.9,
        "category": "DDoS"
    }
]

print("\n" + "=" * 70)
print("THREAT NOTIFICATION TEST")
print("=" * 70)

# Get subscriptions
subscriptions = ThreatSubscription.query.filter_by(is_active=True).all()
print(f"\nActive subscriptions: {len(subscriptions)}")
for sub in subscriptions:
    print(f"  - User {sub.user_id}: {sub.email} (min_risk={sub.min_risk_score})")

# Token store (in-memory)
block_tokens_store = {}

notifications_sent = 0

for threat in sample_threats:
    print(f"\n[THREAT] Processing {threat['indicator']} (score={threat['score']})")
    
    for subscription in subscriptions:
        # Check if threat meets user's risk threshold
        if threat['score'] < subscription.min_risk_score:
            print(f"  [SKIP] Score {threat['score']} < threshold {subscription.min_risk_score} for user {subscription.user_id}")
            continue
        
        # Get user
        from app import User
        user = User.query.get(subscription.user_id)
        if not user:
            print(f"  [ERROR] User {subscription.user_id} not found")
            continue
        
        # Generate token
        token = generate_block_token(
            user_id=user.id,
            ip_address=threat['indicator'],
            threat_data=threat
        )
        
        block_tokens_store[token] = {
            'user_id': user.id,
            'ip_address': threat['indicator'],
            'threat_type': threat.get('type'),
            'risk_score': threat.get('score'),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Build URLs
        import os
        base_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        block_url = f"{base_url}/block-threat?token={token}"
        unsubscribe_url = f"{base_url}/settings?unsubscribe=true"
        
        # Prepare threat data for email
        threat_data = {
            'ip_address': threat['indicator'],
            'threat_type': threat.get('type', 'Unknown IP'),
            'risk_category': threat.get('severity', 'High'),
            'risk_score': threat.get('score', 0),
            'summary': threat.get('summary', 'No description available'),
            'detected_when': 'Just now'
        }
        
        # Send email
        print(f"  [EMAIL] Sending to {user.username} ({subscription.email})...")
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
            print(f"  [SUCCESS] Email sent!")
            
            # Log action
            action_log = ThreatActionLog(
                user_id=user.id,
                action='email_sent',
                ip_address=threat['indicator'],
                performed_by_user_id=None,
                details=json.dumps({
                    'threat_type': threat.get('type'),
                    'risk_score': threat.get('score'),
                    'sent_to': subscription.email,
                    'via': 'manual_test'
                })
            )
            db.session.add(action_log)
        else:
            print(f"  [FAILED] Email sending failed")

db.session.commit()

print(f"\n" + "=" * 70)
print(f"RESULT: Sent {notifications_sent} notifications")
print("=" * 70 + "\n")

print("Tokens generated:")
for token in list(block_tokens_store.keys())[:3]:
    data = block_tokens_store[token]
    print(f"  {token[:30]}... -> User {data['user_id']} blocks {data['ip_address']}")
