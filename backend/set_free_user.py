from app import app, db, User, ThreatSubscription

with app.app_context():
    # Update CTI user to free subscription for testing
    cti_user = User.query.filter_by(username="CTI").first()
    if cti_user:
        print(f"Found user: {cti_user.username}")
        print(f"Current subscription: {cti_user.subscription}")
        
        # Change to free
        cti_user.subscription = "free"
        db.session.commit()
        
        # Refresh to get updated values
        db.session.refresh(cti_user)
        
        print(f"✅ Updated to: {cti_user.subscription}")
        print(f"is_premium check: {cti_user.subscription == 'premium'}")
    else:
        print("❌ CTI user not found")
    
    print("\n=== ALL USERS ===")
    for user in User.query.all():
        is_prem = user.subscription == "premium"
        print(f"{user.username}: {user.subscription} (is_premium={is_prem})")
