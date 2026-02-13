"""
Force send a test notification by clearing recent logs
"""
import json
from datetime import datetime, timedelta
from app import app, db, ThreatSubscription, User, ThreatActionLog, mail
from email_service import send_threat_notification_email

with app.app_context():
    print("\n" + "="*60)
    print("FORCE NOTIFICATION TEST")
    print("="*60)
    
    # Clear recent notification logs (last 2 hours)
    cutoff = datetime.utcnow() - timedelta(hours=2)
    recent_logs = ThreatActionLog.query.filter(
        ThreatActionLog.timestamp > cutoff,
        ThreatActionLog.action == 'email_sent'
    ).all()
    
    print(f"\n🗑️  Clearing {len(recent_logs)} recent notification logs...")
    for log in recent_logs:
        db.session.delete(log)
    db.session.commit()
    print("✅ Cleared")
    
    # Get an active subscription
    subscription = ThreatSubscription.query.filter_by(is_active=True).first()
    if not subscription:
        print("\n❌ No active subscriptions found!")
        exit(1)
    
    user = User.query.get(subscription.user_id)
    print(f"\n📧 Sending test notification to: {user.username} ({subscription.email})")
    
    # Load a high-risk threat from cache
    with open("recent_threats.json", "r") as f:
        threats = json.load(f)
    
    from threat_processor import is_valid_ip
    
    # Find first IP-based high-risk threat
    test_threat = None
    for t in threats:
        if t.get("score", 0) >= 75:
            ip = t.get("ip") or t.get("ip_address") or t.get("indicator")
            if ip and is_valid_ip(ip):
                test_threat = t
                break
    
    if not test_threat:
        print("❌ No IP-based high-risk threats found in cache!")
        exit(1)
    
    ip_address = test_threat.get("ip") or test_threat.get("ip_address") or test_threat.get("indicator")
    print(f"   Threat: {ip_address}")
    print(f"   Score: {test_threat.get('score')}")
    print(f"   Type: {test_threat.get('type')}")
    
    # Prepare email data
    is_premium = (hasattr(user, 'subscription') and user.subscription == "premium")
    
    threat_data = {
        'ip_address': ip_address,
        'threat_type': test_threat.get('type', 'Unknown'),
        'risk_category': test_threat.get('severity', 'High'),
        'risk_score': test_threat.get('score', 0),
        'summary': test_threat.get('summary', 'High-risk threat detected'),
        'detected_when': test_threat.get('timestamp', datetime.utcnow().isoformat()),
        'prevention': test_threat.get('prevention', ''),
        'prevention_steps': test_threat.get('prevention_steps', ''),
        'category': test_threat.get('category', 'Unknown'),
        'notification_type': 'expanded' if is_premium else 'brief'
    }
    
    block_url = "http://localhost:3000/dashboard"
    unsubscribe_url = "http://localhost:3000/settings"
    
    print(f"\n📤 Sending email...")
    try:
        result = send_threat_notification_email(
            mail=mail,
            recipient_email=subscription.email,
            recipient_name=user.username,
            threat_data=threat_data,
            block_url=block_url,
            unsubscribe_url=unsubscribe_url,
            is_premium=is_premium
        )
        
        if result:
            print(f"✅ Email sent successfully to {subscription.email}!")
            print(f"   Check your inbox at: {subscription.email}")
            
            # Log it
            action_log = ThreatActionLog(
                user_id=user.id,
                action='email_sent',
                ip_address=ip_address,
                performed_by_user_id=None,
                details='Manual test notification'
            )
            db.session.add(action_log)
            db.session.commit()
        else:
            print(f"❌ Email failed to send!")
            print(f"   Check SMTP settings in .env file")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        import traceback
        traceback.print_exc()
    
    print("="*60 + "\n")
