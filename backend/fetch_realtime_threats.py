"""
Real-Time Threat Fetcher from AlienVault OTX with Robust Duplicate Prevention

This script fetches threats from OTX and ensures no duplicates by:
1. Checking existing threats in database by indicator_value and otx_id
2. Using in-memory set to prevent duplicates within the same fetch
3. Updating existing threats with fresh data
4. Inserting only new unique threats

Usage:
    python fetch_realtime_threats.py --limit 50 --modified_since 24h
    python fetch_realtime_threats.py --continuous --interval 300
"""

import os
import sys
import json
import argparse
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database imports
from flask import Flask
from models import db, ThreatIndicator

# Configuration
API_KEY = os.getenv("API_KEY")
API_EXPORT_URL = os.getenv("API_EXPORT_URL") or "https://otx.alienvault.com/api/v1/indicators/export"
DATABASE_URI = os.getenv("DATABASE_URL") or "sqlite:///threats.db"

# Initialize Flask app for database context
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Statistics tracking
class FetchStats:
    def __init__(self):
        self.total_fetched = 0
        self.duplicates_skipped = 0
        self.new_threats = 0
        self.updated_threats = 0
        self.errors = 0
        self.start_time = None
        self.end_time = None
    
    def reset(self):
        self.__init__()
    
    def summary(self) -> str:
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        return (
            f"\n{'='*60}\n"
            f"📊 FETCH STATISTICS\n"
            f"{'='*60}\n"
            f"⏱️  Duration: {duration:.2f}s\n"
            f"📥 Total Fetched: {self.total_fetched}\n"
            f"✨ New Threats: {self.new_threats}\n"
            f"🔄 Updated Threats: {self.updated_threats}\n"
            f"🚫 Duplicates Skipped: {self.duplicates_skipped}\n"
            f"❌ Errors: {self.errors}\n"
            f"{'='*60}\n"
        )

stats = FetchStats()


def normalize_indicator(indicator: dict, pulse_title: str = "") -> dict:
    """
    Normalize raw OTX indicator into unified format with deduplication keys.
    """
    indicator_value = (
        indicator.get("indicator") or 
        indicator.get("value") or 
        indicator.get("hostname") or 
        indicator.get("domain") or 
        indicator.get("ip") or 
        str(indicator.get("id", ""))
    )
    
    indicator_type = (
        indicator.get("type") or 
        indicator.get("indicator_type") or 
        ""
    ).lower()
    
    # Extract OTX ID for deduplication
    otx_id = str(indicator.get("id", "")) if indicator.get("id") else None
    
    # Extract pulse information
    pulse_info = indicator.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    pulse_count = len(pulses)
    
    # Extract tags
    tags = set()
    if "tags" in indicator:
        tags.update(str(t).lower() for t in indicator.get("tags", []))
    for pulse in pulses:
        if "tags" in pulse:
            tags.update(str(t).lower() for t in pulse.get("tags", []))
    
    # Categorize based on tags and type
    category = categorize_threat(indicator_type, list(tags))
    
    # Calculate severity score
    severity_data = calculate_severity(indicator, pulses)
    
    # Extract timestamps
    created = indicator.get("created") or indicator.get("first_seen")
    modified = indicator.get("modified") or indicator.get("last_seen")
    
    return {
        "indicator": indicator_value,
        "type": indicator_type,
        "category": category,
        "severity": severity_data["severity"],
        "score": severity_data["score"],
        "pulse_count": pulse_count,
        "reputation": severity_data.get("reputation", 0.0),
        "summary": generate_summary(indicator, category, pulse_count),
        "otx_id": otx_id,
        "first_seen": created,
        "last_seen": modified,
        "tags": list(tags)
    }


def categorize_threat(indicator_type: str, tags: List[str]) -> str:
    """Categorize threat based on type and tags."""
    tags_str = " ".join(tags).lower()
    
    # Category keyword mapping (matches frontend dropdown)
    if any(kw in tags_str for kw in ["phish", "credential", "spoof"]):
        return "Phishing"
    elif any(kw in tags_str for kw in ["ransom", "locker", "encryptor"]):
        return "Ransomware"
    elif any(kw in tags_str for kw in ["malware", "trojan", "virus", "worm", "botnet"]):
        return "Malware"
    elif any(kw in tags_str for kw in ["ddos", "denial", "dos"]):
        return "DDoS Attacks"
    elif any(kw in tags_str for kw in ["cve", "exploit", "vulnerab", "rce", "0day", "zero-day"]):
        return "Vulnerability Exploits"
    elif indicator_type in ["ipv4", "ip", "hostname", "dns", "domain"]:
        return "Current Threats"
    elif indicator_type in ["url", "uri"]:
        return "Malware"
    else:
        return "Other"


def calculate_severity(indicator: dict, pulses: List[dict]) -> Dict[str, Any]:
    """Calculate severity score and level (Low/Medium/High)."""
    base_score = 30.0
    
    # Factor 1: Pulse count (more pulses = higher severity)
    pulse_bonus = min(len(pulses) * 5, 30)
    
    # Factor 2: Confidence from pulses
    confidences = []
    for pulse in pulses:
        conf = pulse.get("confidence") or pulse.get("indicator_type_confidence")
        if conf:
            try:
                confidences.append(float(conf))
            except:
                pass
    avg_confidence = sum(confidences) / len(confidences) if confidences else 50.0
    confidence_bonus = (avg_confidence / 100) * 20
    
    # Factor 3: References count
    ref_count = sum(len(pulse.get("references", [])) for pulse in pulses)
    ref_bonus = min(ref_count * 2, 20)
    
    # Calculate final score
    score = min(base_score + pulse_bonus + confidence_bonus + ref_bonus, 100.0)
    
    # Determine severity level
    if score >= 75:
        severity = "High"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "Low"
    
    # Calculate reputation (0.0 to 1.0)
    reputation = min(score / 100.0, 1.0)
    
    return {
        "score": round(score, 2),
        "severity": severity,
        "reputation": round(reputation, 2)
    }


def generate_summary(indicator: dict, category: str, pulse_count: int) -> str:
    """Generate a brief summary for the threat."""
    indicator_type = indicator.get("type", "unknown").upper()
    indicator_value = indicator.get("indicator", "")[:50]
    
    return f"{category} threat ({indicator_type}): {indicator_value} - Referenced in {pulse_count} pulse(s)"


def fetch_from_otx(limit: int = 50, modified_since: str = "24h") -> List[dict]:
    """
    Fetch indicators from OTX API.
    
    Args:
        limit: Maximum number of indicators to fetch
        modified_since: Time range (e.g., "1h", "24h", "7d")
    
    Returns:
        List of raw indicator dictionaries
    """
    headers = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}
    
    # Oversample to ensure we get enough valid indicators
    fetch_limit = max(limit * 3, limit + 50)
    params = {
        "limit": fetch_limit,
        "modified_since": modified_since
    }
    
    print(f"\n🔍 Fetching from OTX API...")
    print(f"   Limit: {fetch_limit}, Modified Since: {modified_since}")
    
    try:
        response = requests.get(
            API_EXPORT_URL, 
            headers=headers, 
            params=params, 
            timeout=30
        )
        response.raise_for_status()
        
        # Try parsing as JSON
        try:
            data = response.json()
        except:
            # Parse NDJSON (newline-delimited JSON)
            lines = [l.strip() for l in response.text.splitlines() if l.strip()]
            data = []
            for line in lines[:fetch_limit]:
                try:
                    data.append(json.loads(line))
                except:
                    pass
        
        # Extract indicators from response
        if isinstance(data, dict):
            indicators = data.get("results", []) or data.get("indicators", [])
        elif isinstance(data, list):
            indicators = data
        else:
            indicators = []
        
        print(f"✅ Fetched {len(indicators)} raw indicators from OTX")
        return indicators
        
    except requests.exceptions.Timeout:
        print("❌ ERROR: OTX API request timed out (30s)")
        stats.errors += 1
        return []
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR: Failed to fetch from OTX: {e}")
        stats.errors += 1
        return []


def check_existing_threats(indicators: List[dict]) -> Dict[str, ThreatIndicator]:
    """
    Check which indicators already exist in database.
    
    Returns:
        Dictionary mapping indicator_value -> ThreatIndicator object
    """
    print("\n🔍 Checking for existing threats in database...")
    
    # Extract all indicator values and OTX IDs
    indicator_values = set()
    otx_ids = set()
    
    for ind in indicators:
        val = (
            ind.get("indicator") or 
            ind.get("value") or 
            ind.get("hostname") or 
            ind.get("domain") or 
            ind.get("ip") or 
            str(ind.get("id", ""))
        )
        if val:
            indicator_values.add(val)
        
        otx_id = str(ind.get("id", "")) if ind.get("id") else None
        if otx_id:
            otx_ids.add(otx_id)
    
    # Query database for existing threats
    existing = {}
    
    # Check by indicator value
    if indicator_values:
        threats_by_value = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_(list(indicator_values))
        ).all()
        for threat in threats_by_value:
            existing[threat.indicator_value] = threat
    
    # Check by OTX ID
    if otx_ids:
        threats_by_otx = ThreatIndicator.query.filter(
            ThreatIndicator.otx_id.in_(list(otx_ids))
        ).all()
        for threat in threats_by_otx:
            if threat.indicator_value not in existing:
                existing[threat.indicator_value] = threat
    
    print(f"   Found {len(existing)} existing threats in database")
    return existing


def process_indicators(indicators: List[dict], limit: int = 50) -> None:
    """
    Process fetched indicators: normalize, check for duplicates, add/update database.
    
    Args:
        indicators: Raw indicators from OTX
        limit: Maximum number of threats to process
    """
    if not indicators:
        print("\n⚠️  No indicators to process")
        return
    
    print(f"\n⚙️  Processing {len(indicators)} indicators...")
    
    # Check existing threats in database
    existing_threats = check_existing_threats(indicators)
    
    # Track processed indicators in this session to avoid duplicates
    seen_in_session: Set[str] = set()
    
    # Allowed indicator types
    allowed_types = {"ipv4", "ip", "hostname", "dns", "domain", "url", "uri", "md5", "sha1", "sha256"}
    
    processed_count = 0
    
    for indicator in indicators:
        if processed_count >= limit:
            break
        
        try:
            # Normalize indicator
            normalized = normalize_indicator(indicator)
            
            indicator_value = normalized["indicator"]
            indicator_type = normalized["type"].lower()
            otx_id = normalized.get("otx_id")
            
            # Skip if invalid type
            if indicator_type not in allowed_types:
                continue
            
            # Skip if already processed in this session
            if indicator_value in seen_in_session:
                stats.duplicates_skipped += 1
                continue
            
            seen_in_session.add(indicator_value)
            stats.total_fetched += 1
            
            # Check if threat exists in database
            if indicator_value in existing_threats:
                # Update existing threat
                threat = existing_threats[indicator_value]
                threat.last_seen = datetime.utcnow()
                threat.pulse_count = normalized["pulse_count"]
                threat.score = normalized["score"]
                threat.severity = normalized["severity"]
                threat.reputation = normalized["reputation"]
                threat.summary = normalized["summary"]
                
                print(f"   🔄 Updated: {indicator_value} ({indicator_type}) - Score: {normalized['score']}")
                stats.updated_threats += 1
            else:
                # Add new threat
                threat = ThreatIndicator(
                    indicator_value=indicator_value,
                    indicator_type=indicator_type,
                    category=normalized["category"],
                    severity=normalized["severity"],
                    score=normalized["score"],
                    summary=normalized["summary"],
                    pulse_count=normalized["pulse_count"],
                    reputation=normalized["reputation"],
                    otx_id=otx_id,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                db.session.add(threat)
                
                print(f"   ✨ New: {indicator_value} ({indicator_type}) - {normalized['severity']} [{normalized['score']}]")
                stats.new_threats += 1
            
            processed_count += 1
            
        except Exception as e:
            print(f"   ❌ Error processing indicator: {e}")
            stats.errors += 1
            continue
    
    # Commit all changes
    try:
        db.session.commit()
        print(f"\n✅ Successfully committed {stats.new_threats + stats.updated_threats} changes to database")
    except Exception as e:
        db.session.rollback()
        print(f"\n❌ ERROR: Failed to commit to database: {e}")
        stats.errors += 1


def fetch_and_store_threats(limit: int = 50, modified_since: str = "24h") -> None:
    """
    Main function to fetch threats from OTX and store in database.
    
    Args:
        limit: Maximum number of threats to fetch
        modified_since: Time range for modified threats
    """
    stats.reset()
    stats.start_time = datetime.now()
    
    print("\n" + "="*60)
    print("🚀 REAL-TIME THREAT FETCHER")
    print("="*60)
    print(f"⏰ Started at: {stats.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    with app.app_context():
        # Fetch from OTX
        indicators = fetch_from_otx(limit=limit, modified_since=modified_since)
        
        if not indicators:
            print("\n⚠️  No indicators fetched from OTX")
            return
        
        # Process and store
        process_indicators(indicators, limit=limit)
    
    stats.end_time = datetime.now()
    print(stats.summary())


def continuous_fetch(limit: int = 50, modified_since: str = "1h", interval: int = 300):
    """
    Continuously fetch threats at regular intervals.
    
    Args:
        limit: Number of threats per fetch
        modified_since: Time range for each fetch
        interval: Seconds between fetches
    """
    print("\n" + "="*60)
    print("🔄 CONTINUOUS THREAT MONITORING MODE")
    print("="*60)
    print(f"📊 Fetch Limit: {limit}")
    print(f"⏱️  Interval: {interval}s")
    print(f"🕒 Time Range: {modified_since}")
    print("="*60)
    print("\nPress Ctrl+C to stop...\n")
    
    cycle = 1
    try:
        while True:
            print(f"\n{'─'*60}")
            print(f"🔄 CYCLE {cycle}")
            print(f"{'─'*60}")
            
            fetch_and_store_threats(limit=limit, modified_since=modified_since)
            
            print(f"\n⏸️  Waiting {interval}s until next fetch...")
            time.sleep(interval)
            cycle += 1
            
    except KeyboardInterrupt:
        print("\n\n⛔ Stopped by user")
        print(f"✅ Completed {cycle - 1} fetch cycles")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch real-time threats from AlienVault OTX with duplicate prevention",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of threats to fetch (default: 50)"
    )
    
    parser.add_argument(
        "--modified_since",
        default="24h",
        help="Time range for modified threats: 1h, 6h, 24h, 7d (default: 24h)"
    )
    
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run in continuous mode, fetching at regular intervals"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Interval in seconds for continuous mode (default: 300)"
    )
    
    args = parser.parse_args()
    
    # Verify API key
    if not API_KEY:
        print("❌ ERROR: API_KEY not set in environment variables")
        print("   Please set your AlienVault OTX API key in .env file")
        sys.exit(1)
    
    # Run in appropriate mode
    if args.continuous:
        continuous_fetch(
            limit=args.limit,
            modified_since=args.modified_since,
            interval=args.interval
        )
    else:
        fetch_and_store_threats(
            limit=args.limit,
            modified_since=args.modified_since
        )


if __name__ == "__main__":
    main()
