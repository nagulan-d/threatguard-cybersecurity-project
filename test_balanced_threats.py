import requests
import json

try:
    r = requests.get('http://localhost:5000/api/threats?limit=15')
    data = r.json()
    
    print(f'✅ Threats returned: {len(data)}')
    
    high = sum(1 for t in data if t.get('score', 0) >= 75)
    medium = sum(1 for t in data if 50 <= t.get('score', 0) < 75)
    low = sum(1 for t in data if t.get('score', 0) < 50)
    
    print(f'\n📊 Distribution:')
    print(f'  🔴 High (≥75): {high}')
    print(f'  ⚠️ Medium (50-74): {medium}')
    print(f'  🟢 Low (<50): {low}')
    
    print(f'\n🔍 First 5 threats:')
    for i, t in enumerate(data[:5]):
        indicator = t['indicator'][:40]
        score = t['score']
        severity = t['severity']
        
        # Check if severity matches score
        if score >= 75:
            expected = "High"
        elif score >= 50:
            expected = "Medium"
        else:
            expected = "Low"
        
        match = "✅" if severity == expected else "❌"
        print(f'{match} {i+1}. {indicator:40} | Score: {score:3d} | Severity: {severity}')
    
    # Check for mismatches
    mismatches = []
    for t in data:
        score = t.get('score', 0)
        severity = t.get('severity', '')
        
        if score >= 75 and severity != "High":
            mismatches.append(t)
        elif 50 <= score < 75 and severity != "Medium":
            mismatches.append(t)
        elif score < 50 and severity != "Low":
            mismatches.append(t)
    
    if mismatches:
        print(f'\n❌ Found {len(mismatches)} mismatches!')
        for m in mismatches:
            print(f'  {m["indicator"]} - Score: {m["score"]}, Severity: {m["severity"]}')
    else:
        print(f'\n✅ All severity levels match scores correctly!')
        
except Exception as e:
    print(f'❌ Error: {e}')
