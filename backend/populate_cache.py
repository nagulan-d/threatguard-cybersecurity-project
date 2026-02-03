import json
import random

# Create sample threats with proper structure
sample_threats = []

domains = [
    "malicious-site.com", "phishing-login.net", "fake-bank.org",
    "trojan-download.xyz", "ransomware-c2.biz", "botnet-server.info",
    "exploit-kit.com", "malware-host.net", "scam-website.org",
    "ddos-server.com", "crypto-miner.xyz", "spam-relay.net",
    "data-stealer.com", "keylogger-host.org", "backdoor-server.biz",
    "virus-download.info", "worm-propagation.net", "rootkit-install.com",
    "spyware-collector.org", "adware-pusher.xyz", "fake-update.com",
    "credential-harvester.net", "session-hijack.org", "sql-injection.xyz",
    "xss-payload.com", "buffer-overflow.net", "zero-day-exploit.org",
    "apt-command.biz", "nation-state-malware.info", "advanced-threat.com"
]

ips = [
    "192.168.100.50", "10.0.50.100", "172.16.200.75",
    "203.0.113.42", "198.51.100.88", "45.33.32.156",
    "185.220.101.17", "104.244.74.22", "64.233.160.89",
    "151.101.1.140", "13.107.42.14", "23.50.62.94",
    "74.125.224.72", "162.159.200.1", "52.84.167.90",
    "54.230.1.112", "13.35.33.5", "93.184.216.34",
    "104.244.42.1", "151.101.193.69", "172.217.14.206",
    "216.58.217.78", "13.33.88.235", "54.230.129.59",
    "52.222.128.64", "13.249.0.195", "99.86.208.219",
    "143.204.96.147", "18.155.101.1", "204.79.197.200"
]

urls = [
    "http://malicious-site.com/payload.exe",
    "https://phishing-login.net/secure/login.php",
    "http://fake-bank.org/verify-account",
    "https://trojan-download.xyz/update.msi",
    "http://ransomware-c2.biz/encrypt/decrypt.php",
    "https://botnet-server.info/bot/command.php",
    "http://exploit-kit.com/landing/page.html",
    "https://malware-host.net/download/virus.exe",
    "http://scam-website.org/win-prize/claim.php",
    "https://ddos-server.com/attack/target.php"
]

categories = ["Malware", "Phishing", "Ransomware", "DDoS", "Infrastructure", "Web", "Vulnerabilities"]
severities = ["Low", "Medium", "High"]

# Generate varied threats
for i, domain in enumerate(domains):
    sample_threats.append({
        "indicator": domain,
        "type": "domain",
        "category": random.choice(categories),
        "severity": random.choice(severities),
        "severity_score": random.randint(30, 95),
        "summary": f"Malicious domain {domain} associated with threat activity",
        "prevention": "Block this domain in your firewall and DNS filter",
        "prevention_steps": ["Add to blocklist", "Monitor for DNS queries", "Alert security team"],
        "score": random.randint(40, 90),
        "timestamp": "2026-01-27T00:00:00",
        "alert": random.choice([True, False])
    })

for i, ip in enumerate(ips):
    sample_threats.append({
        "indicator": ip,
        "type": "IPv4",
        "category": random.choice(categories),
        "severity": random.choice(severities),
        "severity_score": random.randint(30, 95),
        "summary": f"Suspicious IP address {ip} detected in threat intelligence",
        "prevention": "Block this IP address in your firewall",
        "prevention_steps": ["Add to IP blocklist", "Review logs", "Investigate connections"],
        "score": random.randint(40, 90),
        "timestamp": "2026-01-27T00:00:00",
        "alert": random.choice([True, False]),
        "ip": ip
    })

for i, url in enumerate(urls):
    sample_threats.append({
        "indicator": url,
        "type": "URL",
        "category": random.choice(categories),
        "severity": random.choice(severities),
        "severity_score": random.randint(30, 95),
        "summary": f"Malicious URL {url} hosting threat content",
        "prevention": "Block this URL in your web filter and email gateway",
        "prevention_steps": ["Add to URL blocklist", "Scan for compromised systems", "Update web filters"],
        "score": random.randint(40, 90),
        "timestamp": "2026-01-27T00:00:00",
        "alert": random.choice([True, False])
    })

# Write to cache file
with open("recent_threats.json", "w", encoding="utf-8") as f:
    json.dump(sample_threats, f, indent=2)

print(f"✅ Created cache with {len(sample_threats)} sample threats")
print(f"   - {len(domains)} domains")
print(f"   - {len(ips)} IPs")
print(f"   - {len(urls)} URLs")
