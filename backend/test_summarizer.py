import os, json
from dotenv import load_dotenv
load_dotenv()

print('Loaded .env GEMINI_API_KEY:', bool(os.getenv('GEMINI_API_KEY')))

# Read a sample indicator (support both list and dict formats)
with open('recent_threats.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

sample = None
if isinstance(data, dict):
    results = data.get('results') or data.get('indicators') or []
    if results:
        sample = results[0]
elif isinstance(data, list):
    if data:
        sample = data[0]

if not sample:
    raise SystemExit('No sample indicator found in recent_threats.json')

print('Sample indicator:', sample.get('indicator') if isinstance(sample, dict) else sample)

# Test summarizer module
try:
    import summarizer
    print('summarizer.client exists:', getattr(summarizer, 'client', None) is not None)
    try:
        summarizer.init_client(os.getenv('GEMINI_API_KEY'))
        print('summarizer.init_client called')
    except Exception as e:
        print('summarizer.init_client error:', e)
    try:
        s = summarizer.summarize_threat(sample, pulse_title='Test Pulse')
        print('summarizer.summarize_threat ->', s)
    except Exception as e:
        print('summarizer.summarize_threat threw:', repr(e))
except Exception as e:
    print('Failed to import summarizer:', repr(e))

# Test summarize_threats module (alternate file)
try:
    import summarize_threats
    print('summarize_threats has model attribute:', hasattr(summarize_threats, 'model'))
    try:
        s2 = summarize_threats.summarize_threat(sample, pulse_title='Test Pulse')
        print('summarize_threats.summarize_threat ->', s2)
    except Exception as e:
        print('summarize_threats.summarize_threat threw:', repr(e))
except Exception as e:
    print('Failed to import summarize_threats:', repr(e))
