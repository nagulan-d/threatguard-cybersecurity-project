"""
Check Notification System Status
This script helps diagnose why automatic notifications aren't working.
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(__file__))

# Set up Flask app context
os.environ['FLASK_APP'] = 'app.py'

from app import app, db, User, ThreatSubscription, ThreatActionLog, THREATS_OUTPUT, THREATS_POLL_INTERVAL

def check_notification_status():
    """Check the status of the notification system"""
    
    with app.app_context():
        print("\n" + "="*60)
        print("🔍 NOTIFICATION SYSTEM DIAGNOSTIC")
        print("="*60 + "\n")
        
        # 1. Check configuration
        print("📋 CONFIGURATION:")
        print(f"  - Notification interval: {THREATS_POLL_INTERVAL} seconds ({THREATS_POLL_INTERVAL//60} minutes)")
        print(f"  - Threats cache file: {THREATS_OUTPUT}")
        print(f"  - Cache file exists: {os.path.exists(THREATS_OUTPUT)}")
        
        if os.path.exists(THREATS_OUTPUT):
            try:
                with open(THREATS_OUTPUT, 'r') as f:
                    threats = json.load(f)
                high_risk = [t for t in threats if t.get('score', 0) >= 75]
                ip_based = []
                for t in high_risk:
                    ip = t.get('ip') or t.get('ip_address') or t.get('indicator')
                    if ip and ip != 'N/A':
                        ip_based.append(t)
                
                print(f"  - Total threats in cache: {len(threats)}")
                print(f"  - High-risk threats (score >= 75): {len(high_risk)}")
                print(f"  - IP-based high-risk threats: {len(ip_based)}")
            except Exception as e:
                print(f"  - Error reading cache: {e}")
        
        print()
        
        # 2. Check users
        print("👥 USERS:")
        users = User.query.all()
        print(f"  - Total users: {len(users)}")
        for user in users:
            print(f"    • {user.username} - {user.email} - Role: {user.role} - Subscription: {user.subscription}")
        print()
        
        # 3. Check subscriptions
        print("📧 THREAT NOTIFICATION SUBSCRIPTIONS:")
        subscriptions = ThreatSubscription.query.all()
        print(f"  - Total subscriptions: {len(subscriptions)}")
        
        if not subscriptions:
            print("  ⚠️  NO SUBSCRIPTIONS FOUND!")
            print("  └─ Users need to subscribe to threat notifications to receive emails")
            print("  └─ Subscribe via: Dashboard → Settings → Enable Threat Notifications")
        else:
            active_subs = [s for s in subscriptions if s.is_active]
            print(f"  - Active subscriptions: {len(active_subs)}")
            
            for sub in subscriptions:
                user = User.query.get(sub.user_id)
                status = "🟢 ACTIVE" if sub.is_active else "⚫ INACTIVE"
                last_notif = sub.last_notification_sent.strftime('%Y-%m-%d %H:%M:%S') if sub.last_notification_sent else "Never"
                print(f"    {status} {user.username} ({sub.email})")
                print(f"       Min risk score: {sub.min_risk_score}")
                print(f"       Last notification: {last_notif}")
        print()
        
        # 4. Check recent notification logs
        print("📜 RECENT NOTIFICATION LOGS (Last 24 hours):")
        recent_logs = ThreatActionLog.query.filter(
            ThreatActionLog.action == 'email_sent',
            ThreatActionLog.timestamp > datetime.utcnow() - timedelta(hours=24)
        ).order_by(ThreatActionLog.timestamp.desc()).limit(10).all()
        
        if not recent_logs:
            print("  ⚠️  NO NOTIFICATIONS SENT IN LAST 24 HOURS")
            print("  This could mean:")
            print("    - No active subscriptions")
            print("    - No high-risk threats detected")
            print("    - Background notification thread not running")
            print("    - All threats already notified within 24h window")
        else:
            print(f"  - Total notifications (24h): {len(recent_logs)}")
            for log in recent_logs:
                user = User.query.get(log.user_id)
                print(f"    • {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {user.username} - IP: {log.ip_address}")
                try:
                    details = json.loads(log.details) if log.details else {}
                    print(f"      Risk score: {details.get('risk_score', 'N/A')}, Type: {details.get('threat_type', 'N/A')}")
                except:
                    pass
        print()
        
        # 5. Check email configuration
        print("📮 EMAIL CONFIGURATION:")
        print(f"  - MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
        print(f"  - MAIL_PORT: {app.config.get('MAIL_PORT')}")
        print(f"  - MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
        print(f"  - MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
        pwd = app.config.get('MAIL_PASSWORD')
        print(f"  - MAIL_PASSWORD: {'✅ Set ({} chars)'.format(len(pwd)) if pwd else '❌ NOT SET'}")
        print()
        
        # 6. Recommendations
        print("💡 RECOMMENDATIONS:")
        
        if not subscriptions:
            print("  1. ⚠️  Subscribe a user to threat notifications:")
            print("     - Login to dashboard as a user")
            print("     - Go to Settings/Threat Alerts")
            print("     - Enable threat notifications")
        
        if not os.path.exists(THREATS_OUTPUT):
            print("  2. ⚠️  Threat cache not found - backend may need to run longer")
            print("     - Wait for first threat fetch cycle")
            print("     - Or manually trigger: curl http://localhost:5000/api/threats")
        
        if os.path.exists(THREATS_OUTPUT):
            try:
                with open(THREATS_OUTPUT, 'r') as f:
                    threats = json.load(f)
                high_risk = [t for t in threats if t.get('score', 0) >= 75]
                if not high_risk:
                    print("  3. ℹ️  No high-risk threats in cache (need score >= 75)")
                    print("     - This is normal if there are no current threats")
                    print("     - Notifications only sent for high-risk threats")
            except:
                pass
        
        print("\n" + "="*60)
        print("✅ DIAGNOSTIC COMPLETE")
        print("="*60 + "\n")
        
        # Summary
        print("📊 SUMMARY:")
        has_subs = len([s for s in subscriptions if s.is_active]) > 0 if subscriptions else False
        has_threats = False
        if os.path.exists(THREATS_OUTPUT):
            try:
                with open(THREATS_OUTPUT, 'r') as f:
                    threats = json.load(f)
                high_risk = [t for t in threats if t.get('score', 0) >= 75]
                has_threats = len(high_risk) > 0
            except:
                pass
        
        has_email = bool(app.config.get('MAIL_PASSWORD'))
        
        print(f"  Active Subscriptions: {'✅ YES' if has_subs else '❌ NO'}")
        print(f"  High-Risk Threats:    {'✅ YES' if has_threats else '❌ NO'}")
        print(f"  Email Configured:     {'✅ YES' if has_email else '❌ NO'}")
        
        if has_subs and has_threats and has_email:
            print("\n  ✅ System is configured correctly!")
            print("  Notifications should be sent every {} minutes.".format(THREATS_POLL_INTERVAL//60))
            print("  Check backend console for '[BACKGROUND]' messages.")
        else:
            print("\n  ⚠️  System is NOT fully configured:")
            if not has_subs:
                print("    - Need active subscriptions")
            if not has_threats:
                print("    - Need high-risk threats in cache")
            if not has_email:
                print("    - Need email credentials in .env")
        
        print()

if __name__ == "__main__":
    check_notification_status()
