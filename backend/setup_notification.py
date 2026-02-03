#!/usr/bin/env python
"""Setup active subscription for threat notifications."""

from app import app, db, ThreatSubscription, User
from datetime import datetime

app.app_context().push()

# Get user 6 (kannan with nagulnavadeep05@gmail.com)
user = User.query.get(6)
if not user:
    print("ERROR: User 6 not found!")
    exit(1)

print(f"Setting up subscription for user: {user.username} ({user.email})")

# Delete old inactive subscription for this user if exists
old_sub = ThreatSubscription.query.filter_by(user_id=user.id).first()
if old_sub:
    db.session.delete(old_sub)
    print(f"✓ Deleted old subscription")

# Create new active subscription
new_sub = ThreatSubscription(
    user_id=user.id,
    email=user.email,
    is_active=True,
    min_risk_score=40.0,  # Lower threshold to catch threats
    subscribed_at=datetime.utcnow()
)
db.session.add(new_sub)
db.session.commit()

print(f"\n[SUCCESS] Created active subscription:")
print(f"  Username: {user.username}")
print(f"  User ID: {user.id}")
print(f"  Email: {user.email}")
print(f"  Active: {new_sub.is_active}")
print(f"  Min Risk Score: {new_sub.min_risk_score}")
print(f"  Subscribed At: {new_sub.subscribed_at}")

# Also create subscription for the other email user found
user7 = User.query.get(7)
if user7:
    old_sub7 = ThreatSubscription.query.filter_by(user_id=user7.id).first()
    if old_sub7:
        db.session.delete(old_sub7)
    
    new_sub7 = ThreatSubscription(
        user_id=user7.id,
        email=user7.email,
        is_active=True,
        min_risk_score=40.0,
        subscribed_at=datetime.utcnow()
    )
    db.session.add(new_sub7)
    db.session.commit()
    
    print(f"\n[SUCCESS] Also activated subscription for:")
    print(f"  Username: {user7.username}")
    print(f"  Email: {user7.email}")

print("\n[INFO] Subscriptions are now active and will receive threat notifications!")
