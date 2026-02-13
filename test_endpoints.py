"""
API Endpoint Integration Test
Verifies that all new endpoints are properly wired
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sentinel-backend'))

print("\n" + "="*60)
print("API ENDPOINT INTEGRATION TEST")
print("="*60)

try:
    # Test imports
    print("\n✓ Testing module imports...")
    from main import app
    from api.v1 import discovery, governance, observability, security
    from core.risk_engine import TrustScoreEvaluator
    from core.scanner import DockerScanner
    from core.event_logger import log, get_logs
    
    print("  ✓ main.py")
    print("  ✓ api.v1.discovery")
    print("  ✓ api.v1.governance")
    print("  ✓ api.v1.observability")
    print("  ✓ core.risk_engine")
    print("  ✓ core.scanner")
    print("  ✓ core.event_logger")
    
    # Check routers exist
    print("\n✓ Checking router configuration...")
    assert hasattr(discovery, 'router'), "discovery router missing"
    assert hasattr(governance, 'router'), "governance router missing"
    assert hasattr(observability, 'router'), "observability router missing"
    assert hasattr(security, 'router'), "security router missing"
    print("  ✓ All routers present")
    
    # Check endpoints in app routes
    print("\n✓ Checking endpoints in FastAPI app...")
    routes = [route.path for route in app.routes]
    
    expected_endpoints = [
        "/api/v1/metrics/summary",
        "/api/v1/system/health",
        "/api/v1/security/alerts",
        "/api/v1/metrics/cost",
        "/api/v1/discovery/shadow-ai",
        "/api/v1/governance/audit-logs",
        "/api/v1/governance/terminate/{container_id}",
        "/api/v1/governance/quarantine/{container_id}",
    ]
    
    found = 0
    for endpoint in expected_endpoints:
        if any(endpoint in route for route in routes):
            print(f"  ✓ {endpoint}")
            found += 1
        else:
            print(f"  ✗ {endpoint} NOT FOUND")
    
    print(f"\n{found}/{len(expected_endpoints)} endpoints configured")
    
    if found == len(expected_endpoints):
        print("\n✓✓✓ ALL ENDPOINTS PROPERLY CONFIGURED ✓✓✓")
        sys.exit(0)
    else:
        print("\n✗✗✗ MISSING ENDPOINTS ✗✗✗")
        sys.exit(1)
        
except Exception as e:
    print(f"\n✗ Integration test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
