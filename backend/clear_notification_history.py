"""
Clear all notification history to allow immediate fresh notifications
"""
from app import app, db, ThreatActionLog

def clear_notification_history():
    """Clear all threat notification logs"""
    with app.app_context():
        try:
            # Delete all notification logs
            deleted = ThreatActionLog.query.filter_by(action='notification').delete()
            db.session.commit()
            print(f"✅ Cleared {deleted} notification logs")
            print("✅ System ready to send immediate notifications!")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    clear_notification_history()
