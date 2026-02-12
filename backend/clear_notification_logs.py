#!/usr/bin/env python
"""Clear recent notification logs to allow retesting."""

from app import app, db, ThreatActionLog
from datetime import datetime, timedelta

app.app_context().push()

# Delete recent notification logs (last 24 hours)
recent_logs = ThreatActionLog.query.filter(
    ThreatActionLog.action == 'email_sent',
    ThreatActionLog.timestamp > datetime.utcnow() - timedelta(hours=24)
).all()

print(f"Found {len(recent_logs)} recent notification logs")

for log in recent_logs:
    db.session.delete(log)

db.session.commit()
print(f"✅ Deleted {len(recent_logs)} notification logs - ready for retesting")
