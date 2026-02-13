#!/usr/bin/env python3
"""
Comprehensive Backend Test Suite
Tests all Trust Intelligence Engine components
"""

import sys
import os
import json
from datetime import datetime

# Add sentinel-backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sentinel-backend'))

def test_risk_engine():
    """Test the new TrustScoreEvaluator"""
    print("\n" + "="*60)
    print("TEST 1: RiskEngine - Trust Score Calculation")
    print("="*60)
    
    try:
        from core.risk_engine import TrustScoreEvaluator, SANCTIONED_IMAGES
        
        # Test 1a: Sanctioned Image
        print("\n✓ Testing sanctioned image (archestra/platform)...")
        test_attrs_sanctioned = {
            "Config": {"User": "root"},
            "HostConfig": {"Privileged": True},
            "NetworkSettings": {"Ports": {}},
        }
        score, details = TrustScoreEvaluator.calculate_trust_score(
            test_attrs_sanctioned, "archestra/platform", {}
        )
        print(f"  Sanctioned image trust score: {score}/100")
        assert score > 50, "Sanctioned image should have higher trust"
        
        # Test 1b: Shadow AI (untrusted)
        print("\n✓ Testing shadow AI (unknown image)...")
        test_attrs_rogue = {
            "Config": {"User": ""},
            "HostConfig": {"Privileged": True, "PortBindings": {"22/tcp": [{"HostIp": "0.0.0.0", "HostPort": "22"}]}},
            "NetworkSettings": {"Ports": {}},
        }
        score, details = TrustScoreEvaluator.calculate_trust_score(
            test_attrs_rogue, "unknown_rogue_image:latest", {}
        )
        print(f"  Shadow AI trust score: {score}/100")
        assert score < 60, "Rogue container should have low trust"
        
        # Test 1c: Verify vectors
        print("\n✓ Verifying all vectors are calculated...")
        assert "vectors" in details
        assert all(v in details["vectors"] for v in ["identity", "configuration", "network", "resources"])
        print(f"  All vectors present: {list(details['vectors'].keys())}")
        
        print("\n✓ RiskEngine tests PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ RiskEngine test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scanner():
    """Test the DockerScanner with new Trust Score"""
    print("\n" + "="*60)
    print("TEST 2: Scanner - Docker Integration")
    print("="*60)
    
    try:
        from core.scanner import DockerScanner, ContainerInfo
        
        print("\n✓ Initializing DockerScanner...")
        scanner = DockerScanner()
        
        if scanner.client is None:
            print("  ⚠ Docker client not available (expected in test environment)")
            print("  Skipping Docker container tests")
            return True
        
        print("\n✓ Scanning containers...")
        containers = scanner.scan_containers()
        print(f"  Found {len(containers)} containers")
        
        if containers:
            for c in containers[:3]:  # Show first 3
                print(f"    - {c.name}: trust_score={c.trust_score}, threat_level={c.threat_level}")
        
        print("\n✓ Scanner tests PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ Scanner test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_models():
    """Test Pydantic models for type safety"""
    print("\n" + "="*60)
    print("TEST 3: Pydantic Models - Type Safety")
    print("="*60)
    
    try:
        from api.v1.observability import HealthMetrics, SecurityAlert, MetricsSummary
        from core.event_logger import AuditLogEntry
        
        # Test HealthMetrics
        print("\n✓ Testing HealthMetrics model...")
        health = HealthMetrics(
            average_trust_score=75.5,
            total_containers=5,
            critical_containers=1,
            healthy_containers=4,
            status="At Risk",
            timestamp=datetime.now().isoformat()
        )
        print(f"  HealthMetrics: {health.status}, avg_trust={health.average_trust_score}")
        
        # Test SecurityAlert
        print("\n✓ Testing SecurityAlert model...")
        alert = SecurityAlert(
            alert_id="test_123",
            timestamp=datetime.now().isoformat(),
            severity="high",
            source="test_container",
            container_id="abc123",
            trust_score=45,
            message="Test alert",
            recommended_action="Investigation required"
        )
        print(f"  SecurityAlert: {alert.message}")
        
        # Test AuditLogEntry
        print("\n✓ Testing AuditLogEntry model...")
        audit = AuditLogEntry(
            id="evt_1",
            timestamp=datetime.now().isoformat(),
            agent_name="test_agent",
            action="Quarantine",
            status="Success",
            details="Test event",
            trust_score_change={"before": 60, "after": 50}
        )
        print(f"  AuditLogEntry: {audit.action} - trust change: {audit.trust_score_change}")
        
        print("\n✓ Model tests PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ Model test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_event_logger():
    """Test enhanced event logging"""
    print("\n" + "="*60)
    print("TEST 4: Event Logger - Audit Trail")
    print("="*60)
    
    try:
        from core.event_logger import log, log_trust_score_change, get_logs
        
        print("\n✓ Testing basic logging...")
        log("test_container", "Scan", "Success", "Container scanned successfully")
        
        print("\n✓ Testing trust score change logging...")
        log_trust_score_change(
            "test_container",
            "abc123",
            75,
            45,
            "Security policy violation"
        )
        
        print("\n✓ Retrieving logs...")
        logs = get_logs()
        print(f"  Total logs: {len(logs)}")
        
        if logs:
            print(f"  Latest log: {logs[0]['action']} - {logs[0]['agentName']}")
            if logs[0].get('trust_score_change'):
                print(f"    Trust change: {logs[0]['trust_score_change']}")
        
        print("\n✓ Event Logger tests PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ Event Logger test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "█"*60)
    print("█  ARCHESTRA SENTINEL - TRUST ENGINE TEST SUITE")
    print("█"*60)
    
    results = {
        "RiskEngine": test_risk_engine(),
        "Scanner": test_scanner(),
        "Models": test_models(),
        "EventLogger": test_event_logger(),
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓✓✓ ALL TESTS PASSED ✓✓✓")
        return 0
    else:
        print(f"\n✗✗✗ {total - passed} TEST(S) FAILED ✗✗✗")
        return 1


if __name__ == "__main__":
    sys.exit(main())
