"""
Quick script to check and create threat subscriptions for all users
"""
from app import app, db, User, ThreatSubscription
from datetime import datetime

with app.app_context():
    # Get all users
    users = User.query.all()
    print(f"\n{'='*60}")
    print(f"CHECKING THREAT SUBSCRIPTIONS")
    print(f"{'='*60}")
    print(f"Total users: {len(users)}\n")
    
    for user in users:
        subscription = ThreatSubscription.query.filter_by(user_id=user.id).first()
        
        if subscription:
            status = "✅ ACTIVE" if subscription.is_active else "❌ INACTIVE"
            print(f"{status} - {user.username} ({user.email})")
            print(f"    Min Risk Score: {subscription.min_risk_score}")
            print(f"    Last Notification: {subscription.last_notification_sent or 'Never'}")
        else:
            # Auto-subscribe all users
            print(f"⚠️  NO SUBSCRIPTION - {user.username} ({user.email})")
            print(f"    Creating subscription now...")
            
            new_subscription = ThreatSubscription(
                user_id=user.id,
                email=user.email,
                is_active=True,
                min_risk_score=75.0
            )
            db.session.add(new_subscription)
            print(f"    ✅ Subscribed!")
        
        print()
    
    db.session.commit()
    
    # Final count
    active_subs = ThreatSubscription.query.filter_by(is_active=True).count()
    print(f"{'='*60}")
    print(f"SUMMARY: {active_subs} active subscriptions")
    print(f"{'='*60}\n")
