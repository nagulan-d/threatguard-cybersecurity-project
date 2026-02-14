"""
Manual Auto-Block Script - Blocks Real High-Risk Threats
This script manually triggers auto-blocking for high-risk threats from the cache.
The blocked IPs will appear in the Admin Dashboard under "Auto-Blocked High-Risk Threats"
"""
import sys
import os
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, _auto_block_high_risk_threats, BlockedThreat, User, THREATS_OUTPUT

def manual_auto_block():
    """Manually trigger auto-blocking for real threats"""
    
    print("=" * 80)
    print("MANUAL AUTO-BLOCK - REAL THREATS")
    print("=" * 80)
    
    with app.app_context():
        # Check for admin user
        admin_user = User.query.filter_by(role="admin").first()
        if admin_user:
            print(f"\n[INFO] Admin user found: {admin_user.username} (ID: {admin_user.id})")
        else:
            print("\n[WARN] No admin user found - one will be created automatically")
        
        # Load real threats from cache
        print(f"\n[LOADING] Reading threats from cache: {THREATS_OUTPUT}")
        try:
            with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
                threats = json.load(f)
            print(f"[OK] Loaded {len(threats)} threats from cache")
        except FileNotFoundError:
            print(f"[ERROR] Cache file not found: {THREATS_OUTPUT}")
            print("[HINT] Make sure the backend has run at least once to populate the cache")
            return
        except Exception as e:
            print(f"[ERROR] Failed to read cache: {e}")
            return
        
        if not threats:
            print("[WARN] No threats in cache - nothing to block")
            return
        
        # Show threat statistics
        high_risk = [t for t in threats if t.get("score", 0) >= 75]
        ip_based_high_risk = [
            t for t in high_risk 
            if (t.get("ip") or t.get("ip_address") or t.get("IP Address") or t.get("indicator"))
        ]
        
        print(f"\n[STATS] Threat Statistics:")
        print(f"  Total threats: {len(threats)}")
        print(f"  High-risk threats (score >= 75): {len(high_risk)}")
        print(f"  High-risk with IPs: {len(ip_based_high_risk)}")
        
        if not ip_based_high_risk:
            print("\n[WARN] No high-risk threats with IPs to block")
            return
        
        # Show sample threats that will be blocked
        print(f"\n[PREVIEW] Sample threats to be blocked (up to 5):")
        for i, threat in enumerate(ip_based_high_risk[:5], 1):
            ip = (
                threat.get("ip") or 
                threat.get("ip_address") or 
                threat.get("IP Address") or 
                threat.get("indicator")
            )
            score = threat.get("score", 0)
            threat_type = threat.get("type") or threat.get("Type") or "Unknown"
            print(f"  {i}. {ip} - {threat_type} (Score: {score})")
        
        # Show current blocked IPs before
        existing_blocks = BlockedThreat.query.filter_by(is_active=True).all()
        print(f"\n[BEFORE] Currently blocked IPs in database: {len(existing_blocks)}")
        
        # Run auto-blocking
        print("\n" + "=" * 80)
        print("[RUNNING] Auto-Blocking System")
        print("=" * 80 + "\n")
        
        _auto_block_high_risk_threats(threats)
        
        # Show results after
        print("\n" + "=" * 80)
        print("[RESULTS] After Auto-Blocking")
        print("=" * 80)
        
        all_blocks = BlockedThreat.query.filter_by(is_active=True).all()
        print(f"\n[AFTER] Total blocked IPs in database: {len(all_blocks)}")
        
        # Show newly blocked IPs
        new_blocks = [b for b in all_blocks if b.id not in {eb.id for eb in existing_blocks}]
        if new_blocks:
            print(f"\n[NEW BLOCKS] {len(new_blocks)} new IPs blocked:")
            for block in new_blocks:
                print(f"  ✓ ID:{block.id} | IP:{block.ip_address} | Type:{block.threat_type} | Score:{block.risk_score}")
                print(f"    Blocked by: {block.blocked_by} | User ID: {block.user_id}")
        else:
            print("\n[INFO] No new IPs were blocked (all were already blocked or skipped)")
        
        # Show admin dashboard access info
        print("\n" + "=" * 80)
        print("[DASHBOARD] How to View in Admin Dashboard")
        print("=" * 80)
        print("\n1. Login to the frontend as admin")
        print("2. Navigate to Admin Dashboard")
        print("3. Go to 'Blocked Threats' tab")
        print("4. Filter by:")
        print("   - Blocked by: admin")
        print("   - Active: true")
        print("5. You should see the auto-blocked IPs listed\n")
        
        # Show API endpoint for verification
        print("[API] You can also verify via API:")
        print(f"  GET http://localhost:5000/api/admin/blocked-threats?blocked_by=admin&is_active=true")
        print("  (Requires admin JWT token in Authorization header)")
        
        print("\n" + "=" * 80)
        print("MANUAL AUTO-BLOCK COMPLETE")
        print("=" * 80)

if __name__ == "__main__":
    manual_auto_block()
