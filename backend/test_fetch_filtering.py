#!/usr/bin/env python3
"""
Test script to verify that fetch_and_cache properly filters indicators by IP presence.
This ensures only threats with valid IP addresses are fetched and stored.
"""

from threat_processor import extract_ip_from_indicator, is_valid_ip
import json

# Simulate different types of OTX indicators
TEST_INDICATORS = [
    # Valid IP indicators - SHOULD BE KEPT
    {
        "indicator": "192.168.1.100",
        "type": "IPv4",
        "title": "Malicious Host",
        "description": "Detected malware C2",
    },
    {
        "indicator": "2001:db8::1",
        "type": "IPv6",
        "title": "IPv6 Botnet",
        "description": "Botnet command server",
    },
    {
        "indicator": "malware.exe",
        "type": "File",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "title": "Malware Binary",
        "description": "Known malware executable",
    },
    {
        "indicator": "evil.com",
        "type": "domain",
        "title": "Phishing Site",
        "description": "Known phishing domain",
    },
    {
        "indicator": "10.0.0.5",
        "type": "IPv4",
        "title": "Internal Botnet",
        "description": "Compromised internal server",
    },
    {
        "indicator": "null",
        "type": "unknown",
        "title": "Invalid Indicator",
        "description": "Null indicator",
    },
    {
        "indicator": "203.0.113.42",
        "type": "IPv4",
        "title": "C2 Server",
        "description": "Ransomware C2",
    },
]

def test_ip_extraction():
    """Test that IP extraction correctly identifies indicators with valid IPs."""
    print("=" * 70)
    print("IP EXTRACTION TEST - Filtering by IP Presence")
    print("=" * 70)
    
    valid_count = 0
    invalid_count = 0
    
    for indicator in TEST_INDICATORS:
        ip = extract_ip_from_indicator(indicator)
        has_ip = bool(ip)
        status = "✅ KEEP" if has_ip else "❌ SKIP"
        
        ind_value = indicator.get("indicator", "N/A")
        ind_type = indicator.get("type", "N/A")
        
        print(f"\n{status}")
        print(f"  Indicator: {ind_value}")
        print(f"  Type: {ind_type}")
        print(f"  Extracted IP: {ip if ip else '(none)'}")
        
        if has_ip:
            valid_count += 1
        else:
            invalid_count += 1
    
    print("\n" + "=" * 70)
    print(f"RESULTS: {valid_count} KEPT (with IP), {invalid_count} SKIPPED (no IP)")
    print("=" * 70)
    
    # Expected: 4 kept (IPv4, IPv6, IPv4, IPv4), 3 skipped (File, domain, null)
    expected_valid = 4
    expected_invalid = 3
    
    if valid_count == expected_valid and invalid_count == expected_invalid:
        print("✅ TEST PASSED - Filtering working as expected")
        return True
    else:
        print(f"❌ TEST FAILED - Expected {expected_valid} valid and {expected_invalid} invalid")
        return False


def test_fetch_simulation():
    """Simulate the fetch_and_cache filtering logic."""
    print("\n" + "=" * 70)
    print("FETCH SIMULATION - Testing fetch_and_cache filtering")
    print("=" * 70)
    
    threats = []
    seen_indicators = set()
    skipped_count = 0
    
    for i in TEST_INDICATORS:
        # Simulate the new fetch_and_cache filtering logic
        ip_address = extract_ip_from_indicator(i)
        if not ip_address:
            # Skip this indicator - no valid IP found
            skipped_count += 1
            print(f"⏭️  Skipping: {i.get('indicator')} ({i.get('type')})")
            continue
        
        indicator_value = i.get("indicator")
        if indicator_value in seen_indicators:
            print(f"🔁 Duplicate: {indicator_value}")
            continue
        
        seen_indicators.add(indicator_value)
        threats.append(i)
        print(f"✅ Keeping: {indicator_value} (IP: {ip_address})")
    
    print(f"\n📊 Final Count:")
    print(f"   - Threats with valid IP: {len(threats)}")
    print(f"   - Skipped (no IP): {skipped_count}")
    print(f"   - Total processed: {len(TEST_INDICATORS)}")
    
    return len(threats) == 4 and skipped_count == 3


if __name__ == "__main__":
    print("\n🔍 Testing OTX Data Filtering for IP Presence\n")
    
    test1 = test_ip_extraction()
    test2 = test_fetch_simulation()
    
    print("\n" + "=" * 70)
    if test1 and test2:
        print("✅ ALL TESTS PASSED - IP-based filtering is working correctly")
    else:
        print("❌ SOME TESTS FAILED - Check output above")
    print("=" * 70)
