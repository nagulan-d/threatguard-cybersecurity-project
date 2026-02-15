# Real-Time Threat Fetcher from OTX

## Overview

This system fetches real-time threat intelligence from AlienVault OTX (Open Threat Exchange) with robust duplicate prevention. It ensures that:

✅ No duplicate threats are stored in the database  
✅ Existing threats are updated with fresh data  
✅ New threats are properly categorized and scored  
✅ Memory and database are both checked for duplicates  

## Features

- **Real-time fetching** from AlienVault OTX API
- **Database-level deduplication** by indicator value and OTX ID
- **In-memory duplicate prevention** within each fetch cycle
- **Automatic categorization** (Phishing, Ransomware, Malware, DDoS, etc.)
- **Severity scoring** (Low/Medium/High with 0-100 score)
- **Continuous monitoring mode** for real-time updates
- **Detailed statistics** and logging

## Installation

### 1. Ensure Required Packages are Installed

```powershell
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Make sure your `.env` file has the following:

```env
# AlienVault OTX API Key (required)
API_KEY=your_otx_api_key_here

# OTX Export Endpoint (default provided)
API_EXPORT_URL=https://otx.alienvault.com/api/v1/indicators/export

# Fetch Settings
THREATS_LIMIT=50          # Number of threats to fetch per cycle
MODIFIED_SINCE=24h        # Time range: 1h, 6h, 24h, 7d, 30d

# Database
DATABASE_URL=sqlite:///data.db
```

### 3. Get Your OTX API Key

1. Sign up at https://otx.alienvault.com
2. Go to Settings → API Integration
3. Copy your API key
4. Add it to your `.env` file

## Usage

### Option 1: One-Time Fetch

Fetch threats once and exit:

```powershell
python fetch_realtime_threats.py --limit 50 --modified_since 24h
```

**Parameters:**
- `--limit N`: Maximum number of threats to fetch (default: 50)
- `--modified_since TIME`: Time range (1h, 6h, 24h, 7d, 30d) (default: 24h)

### Option 2: Continuous Monitoring

Run continuously, fetching at regular intervals:

```powershell
python fetch_realtime_threats.py --continuous --interval 300
```

**Parameters:**
- `--continuous`: Enable continuous mode
- `--interval N`: Seconds between fetches (default: 300 = 5 minutes)
- `--limit N`: Threats per fetch (default: 50)
- `--modified_since TIME`: Time range per fetch (default: 24h)

### Option 3: Quick Test

Test the fetcher with a small sample:

```powershell
python test_fetch_threats.py
```

This will fetch 10 threats as a test and verify everything works.

## Examples

### Example 1: Fetch Last Hour of Threats

```powershell
python fetch_realtime_threats.py --limit 30 --modified_since 1h
```

### Example 2: Continuous Monitoring (Every 5 Minutes)

```powershell
python fetch_realtime_threats.py --continuous --interval 300 --modified_since 1h
```

### Example 3: Large Daily Fetch

```powershell
python fetch_realtime_threats.py --limit 200 --modified_since 24h
```

## Output Example

```
============================================================
🚀 REAL-TIME THREAT FETCHER
============================================================
⏰ Started at: 2026-02-14 15:30:45

🔍 Fetching from OTX API...
   Limit: 150, Modified Since: 24h
✅ Fetched 142 raw indicators from OTX

🔍 Checking for existing threats in database...
   Found 38 existing threats in database

⚙️  Processing 142 indicators...
   ✨ New: 104.244.42.1 (ipv4) - High [82.5]
   🔄 Updated: malicious-site.com (domain) - Score: 75.0
   ✨ New: phishing-attempt.com (domain) - Medium [65.0]
   ...

✅ Successfully committed 104 changes to database

============================================================
📊 FETCH STATISTICS
============================================================
⏱️  Duration: 3.45s
📥 Total Fetched: 142
✨ New Threats: 104
🔄 Updated Threats: 38
🚫 Duplicates Skipped: 15
❌ Errors: 0
============================================================
```

## Duplicate Prevention Strategy

The system uses a **three-layer duplicate prevention strategy**:

### Layer 1: OTX ID Check
- Each OTX threat has a unique ID
- Database stores OTX IDs with unique constraint
- Prevents same threat from being added twice

### Layer 2: Indicator Value Check
- Each threat indicator (IP, domain, hash, URL) is unique
- Database enforces unique constraint on indicator values
- Handles cases where OTX ID might change

### Layer 3: In-Memory Session Tracking
- Tracks processed indicators within each fetch cycle
- Prevents duplicates in the same API response
- Improves performance by avoiding redundant lookups

## Database Schema

The `ThreatIndicator` model stores:

```python
- indicator_value: The actual threat (IP, domain, hash, URL) [UNIQUE]
- indicator_type: Type (ipv4, domain, url, md5, sha256, etc.)
- category: Phishing, Ransomware, Malware, DDoS, etc.
- severity: Low, Medium, High
- score: 0-100 risk score
- summary: Brief description
- pulse_count: Number of OTX pulses referencing this threat
- reputation: 0.0-1.0 reputation score
- otx_id: OTX unique identifier [UNIQUE]
- first_seen: First time detected
- last_seen: Most recent update
```

## Integration with Existing System

The improved `fetch_and_cache()` function in `app.py` has been updated to:

1. ✅ Check database for existing threats before adding
2. ✅ Update existing threats with fresh data
3. ✅ Track duplicates and provide statistics
4. ✅ Maintain the existing cache file format

**No changes needed** to existing code that calls `fetch_and_cache()`.

## Troubleshooting

### Error: "API_KEY not set"

**Solution:** Add your OTX API key to `.env`:
```env
API_KEY=your_api_key_here
```

### Error: "Failed to fetch from OTX"

**Possible causes:**
- Invalid API key
- Network connectivity issues
- OTX API temporarily down

**Solution:** Verify your API key and internet connection.

### Warning: "No indicators fetched from OTX"

**Possible causes:**
- Time range too narrow (no new threats)
- API rate limiting

**Solution:** Try a larger time range (e.g., `--modified_since 24h`)

### Duplicate Constraint Error

**Cause:** Extremely rare race condition

**Solution:** The system automatically handles this via try/catch. Check logs for details.

## Performance Tips

1. **Start Small**: Begin with `--limit 50` and adjust based on your needs
2. **Optimize Interval**: For continuous mode, 300s (5 min) is a good balance
3. **Time Range**: Use `1h` for real-time, `24h` for comprehensive coverage
4. **Database Maintenance**: Periodically clean old threats (optional)

## Monitoring

### View Statistics

Each run provides detailed statistics:
- Total fetched from OTX
- New threats added
- Existing threats updated
- Duplicates prevented
- Processing errors

### Database Queries

Check total threats:
```python
from models import db, ThreatIndicator
print(f"Total threats: {ThreatIndicator.query.count()}")
```

Check recent threats:
```python
recent = ThreatIndicator.query.order_by(ThreatIndicator.last_seen.desc()).limit(10).all()
for threat in recent:
    print(f"{threat.indicator_value} - {threat.severity} [{threat.score}]")
```

## Advanced Usage

### Custom Filtering

Edit `fetch_realtime_threats.py` to customize:
- Allowed indicator types (line ~282)
- Category mappings (line ~123)  
- Severity thresholds (line ~151)

### Database Integration

The fetcher is designed to work with your existing Flask app:

```python
from fetch_realtime_threats import fetch_and_store_threats

# In your Flask app
with app.app_context():
    fetch_and_store_threats(limit=100, modified_since="24h")
```

## Automation

### Windows Task Scheduler

Create a scheduled task to run every hour:

```powershell
# Create a scheduled task
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\path\to\fetch_realtime_threats.py --limit 50 --modified_since 1h" -WorkingDirectory "C:\path\to\backend"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "OTX Threat Fetcher"
```

### Linux Cron

```bash
# Add to crontab (runs every hour)
0 * * * * cd /path/to/backend && python fetch_realtime_threats.py --limit 50 --modified_since 1h
```

## Support

For issues or questions:
1. Check the console output for error messages
2. Verify your `.env` configuration
3. Test with `python test_fetch_threats.py`
4. Check OTX API status at https://otx.alienvault.com

## License

Part of the CTI Auto-Defense System project.
