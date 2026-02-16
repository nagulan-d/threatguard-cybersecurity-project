# Auto-Blocking System Documentation

## Overview
The auto-blocking system automatically blocks high-risk threat IPs detected by the ThreatGuard platform. It works alongside the notification system to provide comprehensive threat protection.

## Features
- **Automatic Blocking**: Blocks high-risk IPs (score >= 75) automatically
- **Rate Limiting**: Blocks one IP at a time with configurable delay
- **Deduplication**: Skips already blocked IPs to avoid duplicates
- **Logging**: Records all blocking actions in the database
- **Configurable**: Fully customizable through environment variables

## Configuration

### Environment Variables (.env)

```bash
# Enable/disable auto-blocking
AUTO_BLOCK_ENABLED=true

# Risk score threshold for auto-blocking (default: 75 = High risk)
AUTO_BLOCK_THRESHOLD=75

# Delay in seconds between blocking each IP (prevents overwhelming the system)
AUTO_BLOCK_DELAY=10

# Maximum IPs to block per cycle (default: 5)
AUTO_BLOCK_MAX_PER_CYCLE=5
```

## How It Works

### 1. Background Processing
The auto-blocking system runs in the `_background_updater()` thread alongside the notification system:
- Runs every `THREATS_POLL_INTERVAL` seconds (default: 120s = 2 minutes)
- Loads cached threats from `recent_threats.json`
- Processes threats for both notifications and blocking

### 2. Threat Filtering
The system filters threats based on:
- **Risk Score**: Only threats with score >= `AUTO_BLOCK_THRESHOLD` (default: 75)
- **IP Presence**: Only threats with valid IP addresses
- **Not Already Blocked**: Skips IPs that are already in the blocked list

### 3. Blocking Process
For each eligible threat:
1. Extract IP address from threat data
2. Check if IP is already blocked (skip if yes)
3. Block IP using the OS-level firewall (via `ip_blocker`)
4. Create `BlockedThreat` database record
5. Log action in `ThreatActionLog`
6. Wait `AUTO_BLOCK_DELAY` seconds before next block
7. Stop after `AUTO_BLOCK_MAX_PER_CYCLE` blocks

### 4. Database Records
Each blocked IP creates:
- **BlockedThreat**: Main blocking record with threat details
- **ThreatActionLog**: Action log entry with metadata

## Example Workflow

```
[BACKGROUND] Cycle starts
  ↓
[NOTIFY] Send email notifications
  ↓
[AUTO-BLOCK] Start auto-blocking
  ↓
Filter threats (score >= 75 + has IP)
  ↓
Found 10 high-risk threats
  ↓
Block IP #1 (192.168.1.100) → Wait 10s
  ↓
Block IP #2 (192.168.1.101) → Wait 10s
  ↓
Block IP #3 (192.168.1.102) → Wait 10s
  ↓
Block IP #4 (192.168.1.103) → Wait 10s
  ↓
Block IP #5 (192.168.1.104) → Stop (max reached)
  ↓
[AUTO-BLOCK] Summary: Blocked=5, Skipped=0, Total=10
  ↓
[BACKGROUND] Cycle complete → Sleep 300s
```

## Testing

### Run Test Script
```bash
cd backend
python test_auto_blocking.py
```

This will:
- Create sample high-risk threats
- Run the auto-blocking system
- Show before/after comparison
- Display blocked vs. skipped IPs

### Expected Output
```
[AUTO-BLOCK] Found 4 high-risk threats eligible for blocking
[AUTO-BLOCK] Currently blocked IPs: 0
[AUTO-BLOCK] [OK] Blocked IP: 192.168.100.101 | Type: Ransomware C2 | Score: 95
[AUTO-BLOCK] Waiting 10s before next block...
[AUTO-BLOCK] [OK] Blocked IP: 192.168.100.102 | Type: Malware Host | Score: 88
...
[AUTO-BLOCK] Summary: Blocked=4, Skipped=1, Total=5
```

## Monitoring

### Console Output
The system provides detailed logging:
- `[AUTO-BLOCK]` prefix for all auto-blocking messages
- `[OK]` for successful blocks
- `[SKIP]` for already blocked IPs
- `[FAIL]` for blocking errors
- `[ERROR]` for system errors

### Example Logs
```
[AUTO-BLOCK] Found 15 high-risk threats eligible for blocking
[AUTO-BLOCK] Currently blocked IPs: 42
[AUTO-BLOCK] [OK] Blocked IP: 203.0.113.45 | Type: Ransomware C2 | Score: 95
[AUTO-BLOCK] Waiting 10s before next block...
[AUTO-BLOCK] [SKIP] IP already blocked: 198.51.100.22
[AUTO-BLOCK] Summary: Blocked=4, Skipped=2, Total=15
```

### Database Queries
Check blocked threats:
```python
from app import app, db, BlockedThreat

with app.app_context():
    # Get all active blocks
    blocks = BlockedThreat.query.filter_by(is_active=True).all()
    
    # Get auto-blocked IPs
    auto_blocks = BlockedThreat.query.filter_by(
        user_id=1,  # System user
        is_active=True
    ).all()
    
    for block in auto_blocks:
        print(f"{block.ip_address} - {block.threat_type} (Score: {block.risk_score})")
```

## Performance Considerations

### Rate Limiting
- **10s delay** between blocks prevents system overload
- **5 blocks per cycle** ensures gradual blocking
- **2-minute cycles** provide consistent protection without overwhelming the firewall

### Resource Usage
- Minimal CPU usage (only during blocking operations)
- Small database footprint (one record per blocked IP)
- OS firewall handles actual blocking (efficient)

## Security Benefits

1. **Immediate Protection**: High-risk IPs blocked within minutes of detection
2. **Defense in Depth**: Works alongside notifications for multi-layered security
3. **OS-Level Blocking**: Uses native firewall for robust protection
4. **Audit Trail**: All actions logged for compliance and investigation

## Troubleshooting

### Auto-blocking not working?
1. Check `AUTO_BLOCK_ENABLED=true` in `.env`
2. Verify background thread is running (check startup logs)
3. Ensure threats cache has high-risk threats (score >= 75)
4. Check firewall permissions (may need admin rights)

### Too many/few blocks?
Adjust configuration:
- `AUTO_BLOCK_MAX_PER_CYCLE`: Increase/decrease blocks per cycle
- `AUTO_BLOCK_THRESHOLD`: Lower threshold = more blocks (caution!)
- `THREATS_POLL_INTERVAL`: More frequent cycles = faster blocking

### Disable auto-blocking temporarily:
```bash
# In .env
AUTO_BLOCK_ENABLED=false
```

Then restart the backend:
```bash
python app.py
```

## Integration with Notifications

The auto-blocking system runs alongside notifications:
1. **Notifications**: Alert users about threats via email
2. **Auto-blocking**: Automatically protect the system
3. **Combined**: Users are notified AND system is protected

Both systems use the same threat data and run in the same background cycle for efficiency.

## Best Practices

1. **Monitor regularly**: Check logs for blocking activity
2. **Review blocks**: Periodically review blocked IPs for false positives
3. **Adjust threshold carefully**: Lower threshold = more aggressive blocking
4. **Keep delay reasonable**: Too short = system overload, too long = slow protection
5. **Test before production**: Use test script to verify configuration

## Future Enhancements

Planned features:
- [ ] Whitelist support for trusted IPs
- [ ] Geographic blocking (block entire regions/countries)
- [ ] Machine learning for adaptive thresholds
- [ ] Webhook notifications for blocked IPs
- [ ] Dashboard widget showing real-time blocking stats
- [ ] Manual unblock from UI
- [ ] Scheduled unblocking (temporary blocks)
