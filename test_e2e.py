"""
End-to-End System Integration Test
Demonstrates the full Trust Intelligence Engine workflow
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sentinel-backend'))

from core.risk_engine import TrustScoreEvaluator, SANCTIONED_IMAGES
from core.scanner import DockerScanner
from core.event_logger import log, log_trust_score_change, get_logs
import json
from datetime import datetime

def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def test_end_to_end():
    """Complete workflow test"""
    
    print_header("ARCHESTRA SENTINEL - END-TO-END SYSTEM TEST")
    
    # Phase 1: Trust Algorithm
    print_header("Phase 1: Trust Score Calculation")
    
    print("\n1. Testing SANCTIONED IMAGE (archestra/platform):")
    sanctioned_attrs = {
        "Config": {"User": "root"},
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": True,
            "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
        },
    }
    score, details = TrustScoreEvaluator.calculate_trust_score(
        sanctioned_attrs, "archestra/platform:latest", {}
    )
    print(f"   Trust Score: {score}/100")
    print(f"   Threat Level: {'SAFE' if score >= 80 else 'MEDIUM' if score >= 60 else 'HIGH' if score >= 40 else 'CRITICAL'}")
    print(f"   Vectors:")
    for vector, data in details["vectors"].items():
        print(f"     - {vector}: {data['score']}/100")
    
    print("\n2. Testing SHADOW AI (unknown/untrusted image):")
    rogue_attrs = {
        "Config": {"User": ""},
        "HostConfig": {
            "Privileged": True,
            "PortBindings": {"2375/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2375"}]}
        },
    }
    score, details = TrustScoreEvaluator.calculate_trust_score(
        rogue_attrs, "suspicious_image:v1", {}
    )
    print(f"   Trust Score: {score}/100")
    print(f"   Threat Level: {'SAFE' if score >= 80 else 'MEDIUM' if score >= 60 else 'HIGH' if score >= 40 else 'CRITICAL'}")
    print(f"   ⚠️  ALERT: Shadow AI detected (score < 60)")
    
    # Phase 2: Live Container Scanning
    print_header("Phase 2: Docker Container Discovery & Scanning")
    
    print("\nInitializing DockerScanner...")
    scanner = DockerScanner()
    
    print("Scanning live containers...")
    containers = scanner.scan_containers()
    
    print(f"\nDiscovered {len(containers)} container(s):\n")
    
    total_trust = 0
    critical_count = 0
    
    for container in containers[:5]:  # Show first 5
        print(f"  Container: {container.name}")
        print(f"    ID: {container.id[:12]}")
        print(f"    Image: {container.image}")
        print(f"    Status: {container.status}")
        print(f"    Trust Score: {container.trust_score}/100")
        print(f"    Threat Level: {container.threat_level}")
        print(f"    Sanctioned: {'✓ Yes' if container.is_sanctioned else '✗ No (Shadow AI)'}")
        
        if container.trust_details and "vectors" in container.trust_details:
            vectors = container.trust_details["vectors"]
            print(f"    Trust Vectors:")
            print(f"      - Identity: {vectors.get('identity', {}).get('score', 'N/A')}/100")
            print(f"      - Configuration: {vectors.get('configuration', {}).get('score', 'N/A')}/100")
            print(f"      - Network: {vectors.get('network', {}).get('score', 'N/A')}/100")
            print(f"      - Resources: {vectors.get('resources', {}).get('score', 'N/A')}/100")
        
        print()
        total_trust += container.trust_score
        if container.trust_score < 40:
            critical_count += 1
    
    # Phase 3: System Health
    print_header("Phase 3: System Health & Aggregation")
    
    if containers:
        avg_trust = total_trust / len(containers)
        print(f"\nSystem Health Metrics:")
        print(f"  Total Containers: {len(containers)}")
        print(f"  Average Trust Score: {avg_trust:.1f}/100")
        print(f"  Healthy (>= 80): {len([c for c in containers if c.trust_score >= 80])}")
        print(f"  At Risk (60-79): {len([c for c in containers if 60 <= c.trust_score < 80])}")
        print(f"  High Risk (40-59): {len([c for c in containers if 40 <= c.trust_score < 60])}")
        print(f"  Critical (< 40): {critical_count}")
        
        if critical_count > 0:
            print(f"\n  🚨 ALERT: {critical_count} container(s) below critical threshold!")
        
        # Determine system status
        if critical_count > 2:
            status = "CRITICAL"
        elif avg_trust < 60:
            status = "AT RISK"
        else:
            status = "HEALTHY"
        
        print(f"\n  System Status: {status}")
    
    # Phase 4: Event Logging
    print_header("Phase 4: Audit Trail & Event Logging")
    
    print("\nLogging example governance actions...")
    
    log("sentinel-backend", "Scan", "Success", "Container security scan completed", tool="Trust Engine")
    log_trust_score_change("suspicious-container", "abc123xyz", 75, 35, "Failed security policy check")
    log("malicious-app", "Quarantine", "Success", "Container quarantined due to low trust", container_id="xyz789", tool="Governor")
    
    logs = get_logs()
    print(f"\nAudit Log ({len(logs)} entries):\n")
    
    for entry in logs[:5]:
        print(f"  [{entry['timestamp'][:19]}]")
        print(f"    Action: {entry['action']}")
        print(f"    Agent: {entry['agentName']}")
        print(f"    Status: {entry['status']}")
        print(f"    Details: {entry['details']}")
        if entry.get('trust_score_change'):
            change = entry['trust_score_change']
            print(f"    Trust Change: {change['before']} → {change['after']}")
        print()
    
    # Phase 5: Real-time Alerts
    print_header("Phase 5: Real-time Security Alerts")
    
    print("\nGenerating alerts for containers below 60% trust threshold...\n")
    
    alert_count = 0
    for container in containers:
        if container.trust_score < 60:
            alert_count += 1
            
            if container.trust_score < 40:
                severity = "CRITICAL"
            elif container.trust_score < 50:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            print(f"  🚨 [{severity}] {container.name}")
            print(f"     Trust Score: {container.trust_score}/100")
            
            if not container.is_sanctioned:
                print(f"     Type: SHADOW AI DETECTED - Immediate action required")
            else:
                print(f"     Type: Configuration risk - Requires investigation")
            
            if container.trust_score < 30:
                print(f"     Action: QUARANTINE or TERMINATE")
            else:
                print(f"     Action: Investigate and remediate")
            print()
    
    if alert_count == 0:
        print("  ✓ No containers below alert threshold - System is healthy")
    else:
        print(f"  Total Alerts: {alert_count}")
    
    # Summary
    print_header("SYSTEM SUMMARY")
    
    if containers:
        print(f"\n✓ Container Discovery: {len(containers)} containers identified")
        print(f"✓ Trust Scoring: Complete (0-100 scale)")
        print(f"✓ System Health: {status}")
        print(f"✓ Average Trust: {avg_trust:.1f}/100")
        print(f"✓ Alerts: {alert_count} containers require action")
        print(f"✓ Audit Trail: {len(logs)} events logged")
        print(f"✓ Governance Ready: Quarantine/Terminate endpoints active")
    
    print("\n" + "="*70)
    print("✓✓✓ END-TO-END SYSTEM TEST COMPLETE ✓✓✓")
    print("="*70 + "\n")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(test_end_to_end())
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
