import json

data = json.load(open('recent_threats.json'))
print('🔍 Verifying threat data consistency...\n')
print(f'Total threats: {len(data)}\n')

all_match = True
for i, t in enumerate(data):
    score = t.get('score', 0)
    severity = t.get('severity', 'Unknown')
    
    if score >= 75:
        expected = 'High'
        color = '🔴 Red'
    elif score >= 50:
        expected = 'Medium'
        color = '⚠️ Yellow'
    else:
        expected = 'Low'
        color = '🟢 Green'
    
    match = '✅' if severity == expected else '❌'
    if severity != expected:
        all_match = False
        print(f'{match} {t["indicator"][:40]:40} | Score: {score:3d} | Expected: {expected:6s} | Got: {severity:6s} | {color}')

if all_match:
    print('✅ All 30 threats have correct severity levels matching their scores!')
    print('\nRisk Distribution:')
    high = sum(1 for t in data if t.get('score', 0) >= 75)
    medium = sum(1 for t in data if 50 <= t.get('score', 0) < 75)
    low = sum(1 for t in data if t.get('score', 0) < 50)
    print(f'  🔴 High (≥75):     {high} threats')
    print(f'  ⚠️ Medium (50-74): {medium} threats')
    print(f'  🟢 Low (<50):      {low} threats')
