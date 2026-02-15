import json

with open('recent_threats.json') as f:
    threats = json.load(f)

print(f"\n📊 Total Threats: {len(threats)}\n")
print("Sample Threats:")
print("="*80)

for i, t in enumerate(threats[:15], 1):
    print(f"{i}. {t['category']:20} | {t['indicator']:30} | Score: {t['score']:5} | Pulses: {t['pulse_count']}")

print("\n" + "="*80)
print("\nCategory Distribution:")
from collections import Counter
cat_count = Counter(t['category'] for t in threats)
for cat, count in cat_count.most_common():
    high = len([t for t in threats if t['category'] == cat and t['score'] >= 75])
    print(f"  {cat:25}: {count:3} threats ({high} high)")
