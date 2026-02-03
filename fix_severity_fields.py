"""
Fix severity field in recent_threats.json to match scores
This ensures severity field is consistent with the score value
"""
import json

def fix_severity(data):
    """Fix severity field based on score"""
    fixed_count = 0
    for threat in data:
        score = threat.get("score", 0)
        old_severity = threat.get("severity", "")
        
        # Calculate correct severity
        if score >= 75:
            new_severity = "High"
        elif score >= 50:
            new_severity = "Medium"
        else:
            new_severity = "Low"
        
        # Update if mismatch
        if old_severity != new_severity:
            threat["severity"] = new_severity
            fixed_count += 1
            print(f"  Fixed: {threat['indicator'][:40]:40} | Score: {score:3d} | {old_severity} → {new_severity}")
    
    return fixed_count

def main():
    # Fix both files
    for filepath in ["recent_threats.json", "backend/recent_threats.json"]:
        try:
            print(f"\n📂 Processing {filepath}...")
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            print(f"   Found {len(data)} threats")
            
            fixed_count = fix_severity(data)
            
            if fixed_count > 0:
                # Write back
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"   ✅ Fixed {fixed_count} threats in {filepath}")
            else:
                print(f"   ✅ All severity fields already correct in {filepath}")
            
            # Verify
            high = sum(1 for t in data if t.get("score", 0) >= 75)
            medium = sum(1 for t in data if 50 <= t.get("score", 0) < 75)
            low = sum(1 for t in data if t.get("score", 0) < 50)
            print(f"   📊 Distribution: High={high}, Medium={medium}, Low={low}")
            
        except FileNotFoundError:
            print(f"   ⚠️ File not found: {filepath}")
        except Exception as e:
            print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    main()
