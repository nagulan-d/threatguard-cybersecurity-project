"""
Check Blocked Threats Database
Shows all blocked threats in the database with details
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, BlockedThreat, User

def check_blocked_threats():
    """Display all blocked threats from database"""
    
    print("=" * 80)
    print("BLOCKED THREATS DATABASE CHECK")
    print("=" * 80)
    
    with app.app_context():
        # Get all blocked threats
        all_blocks = BlockedThreat.query.order_by(BlockedThreat.blocked_at.desc()).all()
        
        print(f"\n[TOTAL] {len(all_blocks)} blocked threats in database\n")
        
        if not all_blocks:
            print("[INFO] No blocked threats found")
            print("[HINT] Run 'python manual_auto_block.py' to block some threats")
            return
        
        # Group by status
        active_blocks = [b for b in all_blocks if b.is_active]
        inactive_blocks = [b for b in all_blocks if not b.is_active]
        
        print(f"[ACTIVE] {len(active_blocks)} active blocks")
        print(f"[INACTIVE] {len(inactive_blocks)} inactive blocks\n")
        
        # Group by blocked_by
        admin_blocks = [b for b in all_blocks if b.blocked_by == 'admin']
        user_blocks = [b for b in all_blocks if b.blocked_by == 'user']
        other_blocks = [b for b in all_blocks if b.blocked_by not in ['admin', 'user']]
        
        print(f"[ADMIN BLOCKS] {len(admin_blocks)} blocked by admin")
        print(f"[USER BLOCKS] {len(user_blocks)} blocked by users")
        if other_blocks:
            print(f"[OTHER] {len(other_blocks)} blocked by other")
        
        print("\n" + "=" * 80)
        print("BLOCKED THREATS DETAILS (Active Only)")
        print("=" * 80 + "\n")
        
        if active_blocks:
            for i, block in enumerate(active_blocks[:20], 1):  # Show first 20
                user = User.query.get(block.user_id)
                blocker = User.query.get(block.blocked_by_user_id) if block.blocked_by_user_id else None
                
                print(f"[{i}] ID: {block.id}")
                print(f"    IP Address: {block.ip_address}")
                print(f"    Threat Type: {block.threat_type}")
                print(f"    Risk Score: {block.risk_score} ({block.risk_category})")
                print(f"    Blocked By: {block.blocked_by}")
                print(f"    User: {user.username if user else 'Unknown'} (ID: {block.user_id})")
                if blocker:
                    print(f"    Blocker: {blocker.username} (ID: {block.blocked_by_user_id})")
                print(f"    Reason: {block.reason}")
                print(f"    Blocked At: {block.blocked_at}")
                print(f"    Status: {'ACTIVE' if block.is_active else 'INACTIVE'}")
                print()
            
            if len(active_blocks) > 20:
                print(f"[INFO] Showing first 20 of {len(active_blocks)} active blocks")
        else:
            print("[INFO] No active blocks found")
        
        print("=" * 80)
        print("ADMIN DASHBOARD FILTER INSTRUCTIONS")
        print("=" * 80)
        print("\nTo see auto-blocked threats in the Admin Dashboard:")
        print("1. Login as admin")
        print("2. Go to Admin Dashboard > Blocked Threats tab")
        print("3. Use filters:")
        print("   - Blocked by: 'admin'")
        print("   - Active: 'true'")
        print(f"\nYou should see {len([b for b in admin_blocks if b.is_active])} admin-blocked threats")
        print("\n" + "=" * 80)

if __name__ == "__main__":
    check_blocked_threats()
