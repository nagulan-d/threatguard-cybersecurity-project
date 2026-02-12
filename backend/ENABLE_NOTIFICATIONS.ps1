# ========================================
# Enable Threat Notifications for Admin User
# ========================================
# Run this script to subscribe the admin user to automatic threat notifications
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Enable Threat Notifications" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Activate virtual environment
Write-Host "[1/2] Activating Python environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

Write-Host "[2/2] Subscribing admin to threat notifications..." -ForegroundColor Yellow
Write-Host ""

# Run Python script to enable notifications
python -c @"
import os
os.environ['FLASK_APP'] = 'app.py'

from app import app, db, User, ThreatSubscription
from datetime import datetime

with app.app_context():
    # Find admin user
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        print('❌ Admin user not found!')
        exit(1)
    
    # Check if already subscribed
    existing = ThreatSubscription.query.filter_by(user_id=admin.id).first()
    
    if existing:
        if existing.is_active:
            print(f'✅ Admin is already subscribed to threat notifications')
            print(f'   Email: {existing.email}')
            print(f'   Min risk score: {existing.min_risk_score}')
        else:
            # Reactivate
            existing.is_active = True
            db.session.commit()
            print(f'✅ Reactivated threat notifications for admin')
            print(f'   Email: {existing.email}')
    else:
        # Create new subscription
        subscription = ThreatSubscription(
            user_id=admin.id,
            email=admin.email if admin.email else 'admin@threatguard.local',
            is_active=True,
            min_risk_score=75.0,  # Only high-risk threats
            subscribed_at=datetime.utcnow()
        )
        db.session.add(subscription)
        db.session.commit()
        print(f'✅ Successfully subscribed admin to threat notifications!')
        print(f'   Email: {subscription.email}')
        print(f'   Min risk score: {subscription.min_risk_score}')
    
    print()
    print('📧 Notifications will be sent every 2 minutes for high-risk threats (score >= 75)')
    print()
"@

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Admin user is now subscribed to automatic threat notifications!" -ForegroundColor Green
Write-Host "Restart the backend to start receiving notifications." -ForegroundColor Yellow
Write-Host ""

Pause
