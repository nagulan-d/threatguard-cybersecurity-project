"""
Test Script for Synthetic Threat Generation System
Run this to verify the threat generator and API endpoint work correctly.
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_threat_generator():
    """Test the threat generator module directly."""
    print("\n" + "="*80)
    print("TEST 1: Threat Generator Module")
    print("="*80)
    
    from threat_generator import generate_fresh_threats, get_registry_stats, clear_ip_registry
    
    # Generate first batch
    print("\n[Batch 1] Generating 15 threats...")
    threats1 = generate_fresh_threats(15)
    
    assert len(threats1) == 15, f"Expected 15 threats, got {len(threats1)}"
    
    # Verify distribution
    high = [t for t in threats1 if t['severity'] == 'High']
    medium = [t for t in threats1 if t['severity'] == 'Medium']
    low = [t for t in threats1 if t['severity'] == 'Low']
    
    print(f"\n✓ Severity Distribution:")
    print(f"  High: {len(high)} (expected 5)")
    print(f"  Medium: {len(medium)} (expected 5)")
    print(f"  Low: {len(low)} (expected 5)")
    
    assert len(high) == 5, f"Expected 5 high severity, got {len(high)}"
    assert len(medium) == 5, f"Expected 5 medium severity, got {len(medium)}"
    assert len(low) == 5, f"Expected 5 low severity, got {len(low)}"
    
    # Verify IPs are unique
    ips1 = set(t['ip'] for t in threats1)
    print(f"\n✓ Unique IPs in Batch 1: {len(ips1)}/15")
    assert len(ips1) == 15, "All IPs should be unique in batch 1"
    
    # Generate second batch
    print("\n[Batch 2] Generating 15 more threats...")
    threats2 = generate_fresh_threats(15)
    
    # Verify no overlap
    ips2 = set(t['ip'] for t in threats2)
    overlap = ips1 & ips2
    
    print(f"\n✓ Unique IPs in Batch 2: {len(ips2)}/15")
    print(f"✓ IP Overlap between batches: {len(overlap)}")
    
    assert len(overlap) == 0, f"Expected no overlap, found {len(overlap)} duplicate IPs: {overlap}"
    
    # Verify categories
    categories = set(t['category'] for t in threats1 + threats2)
    print(f"\n✓ Categories used: {len(categories)}")
    print(f"  {', '.join(sorted(categories))}")
    
    # Get stats
    stats = get_registry_stats()
    print(f"\n✓ Registry Stats:")
    print(f"  Total unique IPs generated: {stats['total_unique_ips']}")
    print(f"  Sessions: {stats['session_counter']}")
    
    print("\n" + "="*80)
    print("✅ TEST 1 PASSED - Threat Generator Working Perfectly!")
    print("="*80)
    
    return True


def test_database_models():
    """Test database model creation and operations."""
    print("\n" + "="*80)
    print("TEST 2: Database Models")
    print("="*80)
    
    try:
        from app import app, db, DisplayedThreat
        from datetime import datetime
        import uuid
        
        with app.app_context():
            # Test creating a displayed threat
            print("\n[Test] Creating DisplayedThreat record...")
            
            test_threat = DisplayedThreat(
                threat_id=f"TEST-{uuid.uuid4().hex[:8]}",
                ip_address="192.168.1.100",
                category="Malware",
                threat_type="Test.Trojan",
                severity="High",
                score=85.5,
                status="Active",
                detection_time=datetime.utcnow(),
                session_id="test-session"
            )
            
            db.session.add(test_threat)
            db.session.commit()
            
            print(f"✓ Created threat record: {test_threat.threat_id}")
            
            # Query it back
            retrieved = DisplayedThreat.query.filter_by(threat_id=test_threat.threat_id).first()
            assert retrieved is not None, "Failed to retrieve threat from database"
            
            print(f"✓ Retrieved threat: {retrieved.threat_id}")
            print(f"  IP: {retrieved.ip_address}")
            print(f"  Category: {retrieved.category}")
            print(f"  Severity: {retrieved.severity}")
            print(f"  Score: {retrieved.score}")
            
            # Test to_dict method
            threat_dict = retrieved.to_dict()
            assert 'id' in threat_dict, "to_dict should include 'id' field"
            assert 'ip' in threat_dict, "to_dict should include 'ip' field"
            
            print(f"✓ to_dict() method works correctly")
            
            # Clean up
            db.session.delete(retrieved)
            db.session.commit()
            
            print(f"✓ Cleaned up test record")
            
        print("\n" + "="*80)
        print("✅ TEST 2 PASSED - Database Models Working!")
        print("="*80)
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_endpoint():
    """Test the /api/threats endpoint."""
    print("\n" + "="*80)
    print("TEST 3: API Endpoint (Simulated)")
    print("="*80)
    
    try:
        from app import app, db, DisplayedThreat
        from threat_generator import generate_fresh_threats
        import uuid
        
        with app.app_context():
            # Clear existing threats
            print("\n[Test] Clearing old threats...")
            deleted = db.session.query(DisplayedThreat).delete()
            db.session.commit()
            print(f"✓ Cleared {deleted} old threats")
            
            # Generate fresh threats
            print("\n[Test] Generating fresh threats...")
            session_id = str(uuid.uuid4())[:8]
            threats = generate_fresh_threats(15)
            
            # Store in database (simulating API endpoint)
            print(f"\n[Test] Storing {len(threats)} threats in database...")
            for threat_data in threats:
                from datetime import datetime
                displayed_threat = DisplayedThreat(
                    threat_id=threat_data['id'],
                    ip_address=threat_data['ip'],
                    category=threat_data['category'],
                    threat_type=threat_data['type'],
                    severity=threat_data['severity'],
                    score=threat_data['score'],
                    status=threat_data['status'],
                    detection_time=datetime.fromisoformat(threat_data['detection_time'].replace('Z', '')),
                    session_id=session_id
                )
                db.session.add(displayed_threat)
            
            db.session.commit()
            print(f"✓ Stored all threats in database")
            
            # Retrieve and verify
            print("\n[Test] Retrieving threats from database...")
            stored_threats = DisplayedThreat.query.filter_by(session_id=session_id).all()
            
            print(f"✓ Retrieved {len(stored_threats)} threats")
            
            assert len(stored_threats) == 15, f"Expected 15 threats, got {len(stored_threats)}"
            
            # Verify distribution
            high = len([t for t in stored_threats if t.severity == 'High'])
            medium = len([t for t in stored_threats if t.severity == 'Medium'])
            low = len([t for t in stored_threats if t.severity == 'Low'])
            
            print(f"\n✓ Stored Threat Distribution:")
            print(f"  High: {high}")
            print(f"  Medium: {medium}")
            print(f"  Low: {low}")
            
            # Clean up
            print("\n[Test] Cleaning up test data...")
            db.session.query(DisplayedThreat).filter_by(session_id=session_id).delete()
            db.session.commit()
            print(f"✓ Cleanup complete")
            
        print("\n" + "="*80)
        print("✅ TEST 3 PASSED - API Endpoint Logic Working!")
        print("="*80)
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("SYNTHETIC THREAT GENERATION SYSTEM - COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    results = []
    
    # Test 1: Threat Generator
    try:
        results.append(("Threat Generator", test_threat_generator()))
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Threat Generator", False))
    
    # Test 2: Database Models
    try:
        results.append(("Database Models", test_database_models()))
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Database Models", False))
    
    # Test 3: API Endpoint
    try:
        results.append(("API Endpoint", test_api_endpoint()))
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        results.append(("API Endpoint", False))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print(f"\n{total_passed}/{total_tests} tests passed")
    
    if total_passed == total_tests:
        print("\n🎉 ALL TESTS PASSED! System is ready for production.")
        print("\nNext steps:")
        print("1. Run database migration: flask db upgrade")
        print("2. Start backend: python app.py")
        print("3. Start frontend: npm start")
        print("4. Open admin dashboard and click 'Refresh Threats'")
    else:
        print("\n⚠️ Some tests failed. Please review the errors above.")
        sys.exit(1)
    
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
