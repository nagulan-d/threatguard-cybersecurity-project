# 🚀 OTX Threat Fetcher - Quick Reference Card

## Prerequisites
✅ API Key in `.env` file: `API_KEY=your_otx_api_key_here`  
✅ Python packages installed: `pip install -r requirements.txt`  
✅ Backend directory: `cd backend`

---

## Quick Commands

### 🧪 Test Setup
```powershell
python test_fetch_threats.py
```

### 📥 Fetch Threats (One-Time)
```powershell
# Fetch 50 threats from last 24 hours
python fetch_realtime_threats.py --limit 50 --modified_since 24h

# Fetch 30 threats from last hour (more recent)
python fetch_realtime_threats.py --limit 30 --modified_since 1h

# Large fetch: 200 threats from last 7 days
python fetch_realtime_threats.py --limit 200 --modified_since 7d
```

### 🔄 Continuous Monitoring
```powershell
# Fetch every 5 minutes
python fetch_realtime_threats.py --continuous --interval 300

# Fetch every 10 minutes with custom limit
python fetch_realtime_threats.py --continuous --interval 600 --limit 30 --modified_since 1h
```

### 📊 Check Database Status
```powershell
# View statistics and health
python check_threat_database.py

# Export sample to JSON
python check_threat_database.py --export
```

### 🎛️ Interactive Launcher
```powershell
.\RUN_THREAT_FETCHER.ps1
```

---

## Time Period Options

| Option | Description |
|--------|-------------|
| `1h`   | Last 1 hour |
| `6h`   | Last 6 hours |
| `12h`  | Last 12 hours |
| `24h`  | Last 24 hours (1 day) |
| `7d`   | Last 7 days (1 week) |
| `30d`  | Last 30 days (1 month) |

---

## Common Scenarios

### 🎯 Scenario 1: First Time Setup
```powershell
# 1. Test configuration
python test_fetch_threats.py

# 2. Initial data load
python fetch_realtime_threats.py --limit 100 --modified_since 7d

# 3. Check results
python check_threat_database.py
```

### 🎯 Scenario 2: Real-Time Monitoring
```powershell
# Start continuous monitoring (runs forever until Ctrl+C)
python fetch_realtime_threats.py --continuous --interval 300 --modified_since 1h
```

### 🎯 Scenario 3: Hourly Scheduled Task
```powershell
# Create Windows Task Scheduler to run this every hour
python fetch_realtime_threats.py --limit 50 --modified_since 1h
```

### 🎯 Scenario 4: Check for Duplicates
```powershell
# View database health (shows if duplicates exist)
python check_threat_database.py
```

---

## Output Examples

### ✅ Success
```
🚀 REAL-TIME THREAT FETCHER
⏰ Started at: 2026-02-14 15:30:45

🔍 Fetching from OTX API...
✅ Fetched 142 raw indicators

✨ New Threats: 104
🔄 Updated: 38
🚫 Duplicates Skipped: 15
```

### ❌ Error: Missing API Key
```
❌ ERROR: API_KEY not set in environment variables
   Please set your AlienVault OTX API key in .env file
```

**Fix:** Add to `.env`: `API_KEY=your_key_here`

### ⚠️ Warning: No New Threats
```
⚠️  No indicators fetched from OTX
```

**Fix:** Try longer time range: `--modified_since 24h` or `--modified_since 7d`

---

## Files Created

| File | Purpose |
|------|---------|
| `fetch_realtime_threats.py` | Main fetcher script |
| `test_fetch_threats.py` | Quick test script |
| `check_threat_database.py` | Database status checker |
| `RUN_THREAT_FETCHER.ps1` | Interactive launcher |
| `REALTIME_THREAT_FETCHER.md` | Full documentation |
| `IMPLEMENTATION_SUMMARY.md` | Implementation details |

---

## Integration with Existing App

The enhanced `fetch_and_cache()` function in `app.py` now:
- ✅ Checks database for duplicates
- ✅ Updates existing threats
- ✅ Works with existing notification and auto-blocking systems
- ✅ No code changes needed!

Your existing Flask app (`python app.py`) automatically uses the improved deduplication.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "API_KEY not set" | Add `API_KEY=your_key` to `.env` |
| "No indicators fetched" | Use longer time range: `--modified_since 24h` |
| "Database locked" | Close other database connections |
| "Failed to fetch from OTX" | Check internet connection and API key |

---

## Statistics

The fetcher tracks:
- 📥 **Total Fetched**: Raw indicators from OTX
- ✨ **New Threats**: Added to database
- 🔄 **Updated Threats**: Existing threats refreshed
- 🚫 **Duplicates Skipped**: Prevented from being added twice
- ❌ **Errors**: Any processing issues

---

## Best Practices

1. ✅ **Start with test**: `python test_fetch_threats.py`
2. ✅ **Initial load**: Use `--modified_since 7d` for first run
3. ✅ **Real-time**: Use `--modified_since 1h` with continuous mode
4. ✅ **Check database**: Run `python check_threat_database.py` periodically
5. ✅ **Monitor logs**: Watch for errors in console output

---

## Get Help

📖 **Full Documentation**: `REALTIME_THREAT_FETCHER.md`  
📝 **Implementation Details**: `IMPLEMENTATION_SUMMARY.md`  
🔧 **Check Status**: `python check_threat_database.py`

---

**Quick Start Right Now:**

```powershell
cd backend
python test_fetch_threats.py
python fetch_realtime_threats.py --limit 50 --modified_since 24h
python check_threat_database.py
```

✅ **That's it! You're done!**
