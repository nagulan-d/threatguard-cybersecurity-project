from app import app, db, User, ThreatSubscription

with app.app_context():
    print("=== USER RECORDS ===")
    users = User.query.all()
    for user in users:
        print(f"User: {user.username}")
        print(f"  Email: {user.email if hasattr(user, 'email') else 'N/A'}")
        print(f"  Role: {user.role}")
        print(f"  Subscription: {user.subscription if hasattr(user, 'subscription') else 'N/A'}")
        print()
    
    print("\n=== THREAT SUBSCRIPTIONS ===")
    subs = ThreatSubscription.query.all()
    for sub in subs:
        user = User.query.get(sub.user_id)
        print(f"User: {user.username if user else 'Unknown'}")
        print(f"  Email: {sub.email}")
        print(f"  Active: {sub.is_active}")
        print(f"  Min Risk Score: {sub.min_risk_score}")
        print()
