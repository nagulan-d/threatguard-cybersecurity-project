#!/usr/bin/env python3
"""
Fix recent_threats.json - Remove conflicting severity_score field
Keep only 'score' as the authoritative risk score
"""
import json
from pathlib import Path

# Read the threat data
threats_file = Path(__file__).parent / "recent_threats.json"

print("📋 Loading threats file...")
with open(threats_file, 'r') as f:
    threats = json.load(f)

print(f"📊 Processing {len(threats)} threats...")

# Fix each threat
fixed_count = 0
for threat in threats:
    if 'severity_score' in threat:
        # Remove the conflicting severity_score field
        del threat['severity_score']
        fixed_count += 1
    
    # Ensure score is an integer (0-100)
    if 'score' in threat:
        threat['score'] = int(threat['score'])

print(f"✅ Fixed {fixed_count} threats (removed severity_score)")

# Calculate severity based on score (for consistency)
for threat in threats:
    score = threat.get('score', 0)
    if score >= 75:
        threat['severity'] = 'High'
    elif score >= 50:
        threat['severity'] = 'Medium'
    else:
        threat['severity'] = 'Low'

# Write back the fixed data
print("💾 Writing fixed data back to file...")
with open(threats_file, 'w') as f:
    json.dump(threats, f, indent=2)

print(f"✅ Successfully fixed {threats_file}")
print(f"\n📊 Risk Distribution:")
high = len([t for t in threats if t.get('score', 0) >= 75])
medium = len([t for t in threats if 50 <= t.get('score', 0) < 75])
low = len([t for t in threats if t.get('score', 0) < 50])
print(f"  🔴 High (≥75): {high} threats")
print(f"  ⚠️  Medium (50-74): {medium} threats")
print(f"  🟢 Low (<50): {low} threats")
