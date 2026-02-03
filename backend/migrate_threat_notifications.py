"""
Database migration to add threat notification and blocking tables.

This migration adds:
1. ThreatSubscription - Track user subscriptions to email notifications
2. BlockedThreat - Track IP addresses blocked by users/admins
3. ThreatActionLog - Audit log for all threat-related actions

Run this migration after updating models.py
"""

from flask import Flask
from models import db, ThreatSubscription, BlockedThreat, ThreatActionLog
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

def migrate():
    """Create new tables for threat notification system."""
    with app.app_context():
        print("🔄 Creating threat notification and blocking tables...")
        
        # Create all tables (will only create missing ones)
        db.create_all()
        
        print("✅ Migration completed successfully!")
        print("\nNew tables created:")
        print("  - threat_subscription (user email notifications)")
        print("  - blocked_threat (IP blocking records)")
        print("  - threat_action_log (audit logs)")
        
        # Verify tables exist
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        required_tables = ['threat_subscription', 'blocked_threat', 'threat_action_log']
        missing = [t for t in required_tables if t not in tables]
        
        if missing:
            print(f"\n⚠️  Warning: Missing tables: {missing}")
        else:
            print("\n✅ All required tables verified!")

if __name__ == "__main__":
    migrate()
