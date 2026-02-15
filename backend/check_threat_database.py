"""
Database Status Checker for Threat Indicators
Shows statistics about stored threats and recent activity.
"""

import os
import sys
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Import Flask app and models
try:
    from app import app, db, ThreatIndicator
except ImportError:
    print("❌ ERROR: Could not import app and models")
    print("   Make sure you're in the backend directory")
    sys.exit(1)

def format_datetime(dt):
    """Format datetime for display"""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def check_database_status():
    """Check and display database statistics"""
    
    print("\n" + "="*70)
    print("📊 THREAT DATABASE STATUS")
    print("="*70)
    
    with app.app_context():
        try:
            # Total threats
            total = ThreatIndicator.query.count()
            print(f"\n📈 Total Threats Stored: {total}")
            
            if total == 0:
                print("\n⚠️  No threats found in database")
                print("   Run: python fetch_realtime_threats.py --limit 50 --modified_since 24h")
                return
            
            # Breakdown by severity
            print("\n🎯 By Severity:")
            high = ThreatIndicator.query.filter_by(severity="High").count()
            medium = ThreatIndicator.query.filter_by(severity="Medium").count()
            low = ThreatIndicator.query.filter_by(severity="Low").count()
            print(f"   High:   {high:>6} ({high/total*100:.1f}%)")
            print(f"   Medium: {medium:>6} ({medium/total*100:.1f}%)")
            print(f"   Low:    {low:>6} ({low/total*100:.1f}%)")
            
            # Breakdown by type
            print("\n🔍 By Type:")
            types = db.session.query(
                ThreatIndicator.indicator_type,
                db.func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.indicator_type).order_by(
                db.func.count(ThreatIndicator.id).desc()
            ).all()
            
            for ind_type, count in types[:10]:  # Top 10
                print(f"   {ind_type:15} {count:>6} ({count/total*100:.1f}%)")
            
            # Breakdown by category
            print("\n📂 By Category:")
            categories = db.session.query(
                ThreatIndicator.category,
                db.func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.category).order_by(
                db.func.count(ThreatIndicator.id).desc()
            ).all()
            
            for cat, count in categories:
                print(f"   {cat:20} {count:>6} ({count/total*100:.1f}%)")
            
            # Recent activity
            print("\n⏰ Recent Activity:")
            
            # Recently added
            now = datetime.utcnow()
            last_hour = now - timedelta(hours=1)
            last_24h = now - timedelta(hours=24)
            last_7d = now - timedelta(days=7)
            
            added_1h = ThreatIndicator.query.filter(
                ThreatIndicator.first_seen >= last_hour
            ).count()
            added_24h = ThreatIndicator.query.filter(
                ThreatIndicator.first_seen >= last_24h
            ).count()
            added_7d = ThreatIndicator.query.filter(
                ThreatIndicator.first_seen >= last_7d
            ).count()
            
            print(f"   Added in last hour:  {added_1h:>6}")
            print(f"   Added in last 24h:   {added_24h:>6}")
            print(f"   Added in last 7 days: {added_7d:>6}")
            
            # Recently updated
            updated_1h = ThreatIndicator.query.filter(
                ThreatIndicator.last_seen >= last_hour
            ).count()
            updated_24h = ThreatIndicator.query.filter(
                ThreatIndicator.last_seen >= last_24h
            ).count()
            
            print(f"\n   Updated in last hour: {updated_1h:>6}")
            print(f"   Updated in last 24h:  {updated_24h:>6}")
            
            # Top 10 most recent threats
            print("\n🔥 Top 10 Most Recent Threats:")
            recent = ThreatIndicator.query.order_by(
                ThreatIndicator.last_seen.desc()
            ).limit(10).all()
            
            print(f"\n   {'Indicator':<40} {'Type':<12} {'Severity':<8} {'Score':<6} {'Last Seen'}")
            print(f"   {'-'*40} {'-'*12} {'-'*8} {'-'*6} {'-'*19}")
            
            for threat in recent:
                indicator = threat.indicator_value[:37] + "..." if len(threat.indicator_value) > 40 else threat.indicator_value
                print(f"   {indicator:<40} {threat.indicator_type:<12} {threat.severity:<8} {threat.score:<6.1f} {format_datetime(threat.last_seen)}")
            
            # Top 10 highest severity
            print("\n⚠️  Top 10 Highest Risk Threats:")
            high_risk = ThreatIndicator.query.filter(
                ThreatIndicator.score >= 75
            ).order_by(
                ThreatIndicator.score.desc()
            ).limit(10).all()
            
            if high_risk:
                print(f"\n   {'Indicator':<40} {'Category':<15} {'Score':<6} {'Pulses'}")
                print(f"   {'-'*40} {'-'*15} {'-'*6} {'-'*7}")
                
                for threat in high_risk:
                    indicator = threat.indicator_value[:37] + "..." if len(threat.indicator_value) > 40 else threat.indicator_value
                    print(f"   {indicator:<40} {threat.category:<15} {threat.score:<6.1f} {threat.pulse_count}")
            else:
                print("   No high-risk threats found (score >= 75)")
            
            # Database health
            print("\n💚 Database Health:")
            
            # Check for duplicates (should be 0)
            duplicates = db.session.query(
                ThreatIndicator.indicator_value,
                db.func.count(ThreatIndicator.id)
            ).group_by(
                ThreatIndicator.indicator_value
            ).having(
                db.func.count(ThreatIndicator.id) > 1
            ).count()
            
            if duplicates == 0:
                print(f"   ✅ No duplicates found")
            else:
                print(f"   ⚠️  {duplicates} duplicate indicators found")
            
            # Check for threats with OTX IDs
            with_otx_id = ThreatIndicator.query.filter(
                ThreatIndicator.otx_id.isnot(None)
            ).count()
            print(f"   ✅ {with_otx_id} threats have OTX IDs ({with_otx_id/total*100:.1f}%)")
            
            # Oldest and newest
            oldest = ThreatIndicator.query.order_by(
                ThreatIndicator.first_seen.asc()
            ).first()
            newest = ThreatIndicator.query.order_by(
                ThreatIndicator.first_seen.desc()
            ).first()
            
            print(f"\n   Oldest threat: {format_datetime(oldest.first_seen) if oldest else 'N/A'}")
            print(f"   Newest threat: {format_datetime(newest.first_seen) if newest else 'N/A'}")
            
        except Exception as e:
            print(f"\n❌ ERROR: Failed to query database: {e}")
            import traceback
            traceback.print_exc()
            return
    
    print("\n" + "="*70)
    print("✅ Database check complete!")
    print("="*70)
    print()

def export_sample():
    """Export a sample of threats to JSON"""
    print("\n🔹 Exporting sample threats to JSON...")
    
    with app.app_context():
        threats = ThreatIndicator.query.order_by(
            ThreatIndicator.score.desc()
        ).limit(20).all()
        
        sample_data = [threat.to_dict() for threat in threats]
        
        import json
        output_file = "threat_sample.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sample_data, f, indent=2, ensure_ascii=False)
        
        print(f"   ✅ Exported {len(sample_data)} threats to {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Check threat database status")
    parser.add_argument("--export", action="store_true", help="Export sample to JSON")
    args = parser.parse_args()
    
    check_database_status()
    
    if args.export:
        export_sample()
