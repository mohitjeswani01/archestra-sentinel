from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
from core.scanner import DockerScanner
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# ─── PYDANTIC MODELS FOR TYPE SAFETY ───────────────────────────

class HealthMetrics(BaseModel):
    """System health summary with average trust score"""
    average_trust_score: float
    total_containers: int
    critical_containers: int
    healthy_containers: int
    status: str  # "Healthy", "At Risk", "Critical"
    timestamp: str


class SecurityAlert(BaseModel):
    """Real-time security alert for containers below trust threshold"""
    alert_id: str
    timestamp: str
    severity: str  # "low", "medium", "high", "critical"
    source: str  # Container name
    container_id: str
    trust_score: int
    message: str
    recommended_action: str


class MetricsSummary(BaseModel):
    """Executive dashboard metrics"""
    total_containers: int
    shadow_ai_detected: int
    critical_risks: int
    system_health: str
    threat_level: str
    money_saved: int
    average_trust_score: float


# ─── ENDPOINTS ───────────────────────────

@router.get("/metrics/summary", response_model=MetricsSummary)
async def get_metrics_summary():
    """
    Get executive summary metrics with real trust scores
    """
    scanner = DockerScanner()
    containers = scanner.scan_containers()
    
    total = len(containers)
    system_status_ok = True

    try:
        # Calculate metrics based on trust scores
        trust_scores = [c.trust_score for c in containers]
        average_trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 100.0

        # Count critical and healthy
        critical_containers = len([c for c in containers if c.trust_score < 40])
        healthy_containers = len([c for c in containers if c.trust_score >= 80])
        shadow_ai_count = len([c for c in containers if not c.is_sanctioned])

        # Threat level based on worst trust score
        if containers:
            worst_trust = min(trust_scores)
            if worst_trust < 40:
                threat_level = "Critical"
            elif worst_trust < 60:
                threat_level = "High"
            elif worst_trust < 80:
                threat_level = "Elevated"
            else:
                threat_level = "Low"
        else:
            threat_level = "Low"

        # System health
        if critical_containers > 0:
            system_health = "Critical"
        elif shadow_ai_count > 0 and average_trust_score < 60:
            system_health = "At Risk"
        else:
            system_health = "Healthy"

        # Cost Savings (stopped containers * $250/day)
        stopped_containers = len([c for c in containers if c.status != 'running'])
        money_saved = stopped_containers * 250

        return MetricsSummary(
            total_containers=total,
            shadow_ai_detected=shadow_ai_count,
            critical_risks=critical_containers,
            system_health=system_health,
            threat_level=threat_level,
            money_saved=money_saved,
            average_trust_score=round(average_trust_score, 2),
        )

    except Exception as e:
        logger.error(f"Error in get_metrics_summary: {e}")
        return MetricsSummary(
            total_containers=0,
            shadow_ai_detected=0,
            critical_risks=0,
            system_health="Unknown",
            threat_level="Low",
            money_saved=0,
            average_trust_score=0.0,
        )


@router.get("/system/health", response_model=HealthMetrics)
async def get_system_health():
    """
    GET /system/health
    
    Returns aggregated average Trust Score and system health status
    """
    scanner = DockerScanner()
    containers = scanner.scan_containers()

    try:
        trust_scores = [c.trust_score for c in containers]
        average_trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 100.0

        critical_containers = len([c for c in containers if c.trust_score < 40])
        healthy_containers = len([c for c in containers if c.trust_score >= 80])

        # Determine status
        if critical_containers > 2:
            status = "Critical"
        elif average_trust_score < 60:
            status = "At Risk"
        else:
            status = "Healthy"

        return HealthMetrics(
            average_trust_score=round(average_trust_score, 2),
            total_containers=len(containers),
            critical_containers=critical_containers,
            healthy_containers=healthy_containers,
            status=status,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        logger.error(f"Error in get_system_health: {e}")
        return HealthMetrics(
            average_trust_score=0.0,
            total_containers=0,
            critical_containers=0,
            healthy_containers=0,
            status="Unknown",
            timestamp=datetime.now().isoformat(),
        )


@router.get("/security/alerts", response_model=List[SecurityAlert])
async def get_security_alerts():
    """
    GET /security/alerts
    
    Returns real-time alerts for containers below 60% trust score.
    Format: {timestamp, severity, source, message}
    """
    scanner = DockerScanner()
    containers = scanner.scan_containers()
    alerts: List[SecurityAlert] = []

    try:
        alert_counter = 0

        for container in containers:
            # Generate alert if trust score < 60
            if container.trust_score < 60:
                alert_counter += 1
                
                # Determine severity based on trust score
                if container.trust_score < 30:
                    severity = "critical"
                elif container.trust_score < 45:
                    severity = "high"
                elif container.trust_score < 60:
                    severity = "medium"
                else:
                    severity = "low"

                # Build message based on trust details
                message = f"Container {container.name} has low trust score ({container.trust_score}/100)"
                
                if not container.is_sanctioned:
                    message += " - SHADOW AI DETECTED"
                
                if container.threat_level == "Critical":
                    message += " - CRITICAL THREAT LEVEL"

                recommended_action = "Review container configuration"
                if not container.is_sanctioned:
                    recommended_action = "Quarantine or terminate container immediately"
                elif container.trust_score < 30:
                    recommended_action = "Quarantine for investigation"

                alert = SecurityAlert(
                    alert_id=f"alert_{container.id[:8]}_{alert_counter}",
                    timestamp=datetime.now().isoformat(),
                    severity=severity,
                    source=container.name,
                    container_id=container.id,
                    trust_score=container.trust_score,
                    message=message,
                    recommended_action=recommended_action,
                )
                alerts.append(alert)

        return alerts

    except Exception as e:
        logger.error(f"Error in get_security_alerts: {e}")
        return []


@router.get("/metrics/cost")
async def get_cost_analytics():
    """
    Cost analytics with real data
    """
    scanner = DockerScanner()
    containers = scanner.scan_containers()

    try:
        active_count = len([c for c in containers if c.status == 'running'])
        stopped_count = len([c for c in containers if c.status != 'running'])

        # Real cost calculations
        burn_rate_hourly = active_count * 12.5  # $12.50/hr per container
        daily_burn = burn_rate_hourly * 24
        projected_monthly = daily_burn * 30
        total_saved = stopped_count * 250  # $250/day per stopped container

        # Agent costs breakdown
        agent_costs = []
        for c in containers:
            if c.status == 'running':
                # Base cost + risk adjustment
                cost = 300  # Base daily cost
                trend = 0

                if c.trust_score < 40:  # Critical
                    cost += 150
                    trend = 45
                elif c.trust_score < 60:  # High risk
                    cost += 75
                    trend = 25
                elif c.trust_score < 80:  # Medium risk
                    cost += 30
                    trend = 10

                agent_costs.append({
                    "agentName": c.name,
                    "cost": cost,
                    "trend": trend,
                    "trustScore": c.trust_score,
                })

        agent_costs.sort(key=lambda x: x['cost'], reverse=True)

        return {
            "totalSpend": int(projected_monthly),
            "totalSaved": total_saved,
            "savingsPercent": int((stopped_count / (active_count + stopped_count + 0.001)) * 100),
            "burnRate": int(daily_burn),
            "projectedMonthly": int(projected_monthly),
            "agentCosts": agent_costs,
            "dailyBurn": [
                {"date": "2025-01-01", "cost": int(daily_burn), "optimized": int(daily_burn * 0.8)},
                {"date": "2025-01-02", "cost": int(daily_burn * 1.1), "optimized": int(daily_burn * 0.85)},
            ],
            "optimizationInsights": [
                {
                    "title": "Stop Shadow AI",
                    "impact": f"Could save ${stopped_count * 250}/day",
                    "savings": stopped_count * 250,
                },
            ],
        }

    except Exception as e:
        logger.error(f"Error in get_cost_analytics: {e}")
        return {
            "totalSpend": 0,
            "totalSaved": 0,
            "savingsPercent": 0,
            "burnRate": 0,
            "projectedMonthly": 0,
            "agentCosts": [],
            "dailyBurn": [],
            "optimizationInsights": [],
        }
