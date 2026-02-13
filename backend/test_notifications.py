"""
Test auto-notification system manually
"""
import json
import os
from app import app, db, ThreatSubscription, User, _send_threat_notifications

with app.app_context():
    print("\n" + "="*60)
    print("MANUAL NOTIFICATION TEST")
    print("="*60)
    
    # Check subscriptions
    subscriptions = ThreatSubscription.query.filter_by(is_active=True).all()
    print(f"\n✅ Active subscriptions: {len(subscriptions)}")
    for sub in subscriptions:
        user = User.query.get(sub.user_id)
        if user:
            print(f"  - {user.username} ({sub.email}) - min_risk: {sub.min_risk_score}")
    
    # Check cache file
    cache_file = "recent_threats.json"
    if not os.path.exists(cache_file):
        print(f"\n❌ Cache file not found: {cache_file}")
        print("Run the backend to fetch threats first!")
    else:
        with open(cache_file, "r") as f:
            threats = json.load(f)
        
        print(f"\n✅ Loaded {len(threats)} threats from cache")
        
        # Count high-risk threats
        high_risk = [t for t in threats if t.get("score", 0) >= 75]
        print(f"   High-risk threats (score >= 75): {len(high_risk)}")
        
        # Count IP-based high-risk threats
        from threat_processor import is_valid_ip
        ip_based = []
        for t in high_risk:
            ip = t.get("ip") or t.get("ip_address") or t.get("indicator")
            if ip and is_valid_ip(ip):
                ip_based.append(t)
        
        print(f"   IP-based high-risk threats: {len(ip_based)}")
        
        if ip_based:
            print(f"\n   Sample high-risk threats:")
            for i, t in enumerate(ip_based[:3], 1):
                ip = t.get("ip") or t.get("ip_address") or t.get("indicator")
                print(f"   {i}. {ip} - Score: {t.get('score')} - Type: {t.get('type')}")
        
        # Test sending notifications
        if len(ip_based) > 0 and len(subscriptions) > 0:
            print(f"\n🔔 Sending test notifications...")
            _send_threat_notifications(threats)
            print(f"\n✅ Notification test complete!")
        else:
            if len(ip_based) == 0:
                print(f"\n⚠️  No IP-based high-risk threats to notify about")
            if len(subscriptions) == 0:
                print(f"\n⚠️  No active subscriptions")
    
    print("="*60 + "\n")
