#!/usr/bin/env python3
from app import app, db, BlockedThreat

with app.app_context():
    count = BlockedThreat.query.count()
    print(f'Total blocked threats in DB: {count}')
    
    threats = BlockedThreat.query.limit(10).all()
    print(f'\nFirst {len(threats)} entries:')
    for t in threats:
        print(f'  {t.ip_address} - {t.threat_type} - Score: {t.risk_score}')
