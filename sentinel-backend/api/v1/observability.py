from fastapi import APIRouter
from core.scanner import DockerScanner

router = APIRouter()

@router.get("/metrics/summary")
async def get_metrics_summary():
    scanner = DockerScanner()
    containers = scanner.scan_containers()
    
    total = len(containers)
    shadow_ai_count = len([c for c in containers if not c.is_sanctioned])
    
    # Calculate Threat Level
    max_risk = 0
    if containers:
        max_risk = max([c.risk_score for c in containers])
    
    if max_risk >= 80:
        threat_level = "Critical"
    elif max_risk >= 50:
        threat_level = "High"
    elif max_risk >= 20:
        threat_level = "Elevated"
    else:
        threat_level = "Low"

    critical_risks = len([c for c in containers if c.risk_score >= 80])
    
    # Calculate Cost Savings (Real)
    # Logic: Count exited/stopped containers as "saved" cost. 
    # Assume $250/day per container as per user request.
    stopped_containers = len([c for c in containers if c.status != 'running'])
    money_saved = stopped_containers * 250
    
    # System health logic
    if critical_risks > 0:
        health = "Critical"
    elif shadow_ai_count > 0:
        health = "At Risk"
    else:
        health = "Healthy"

    return {
        "total_containers": total,
        "shadow_ai_detected": shadow_ai_count,
        "critical_risks": critical_risks,
        "system_health": health,
        "threat_level": threat_level,
        "money_saved": money_saved
    }

@router.get("/metrics/cost")
async def get_cost_analytics():
    # Return simulated cost data structure for the Cost Intelligence dashboard
    scanner = DockerScanner()
    containers = scanner.scan_containers()
    
    active_count = len([c for c in containers if c.status == 'running'])
    stopped_count = len([c for c in containers if c.status != 'running'])
    
    # Real Cost Analytics
    # Active containers cost money. Stopped containers save money.
    # Base cost per container: $12.50/hr (~$300/day)
    # Savings: $250/day per stopped container
    
    burn_rate_hourly = active_count * 12.5 
    daily_burn = burn_rate_hourly * 24
    
    # Lifetime savings (estimate based on current state for demo purposes)
    # In a real system, this would be a historical sum.
    total_saved = stopped_count * 250 
    
    projected_monthly = daily_burn * 30

    # Generate Agent Costs Breakdown
    agent_costs = []
    for c in containers:
        if c.status == 'running':
            # Add some variance based on name hash for demo realism, or fixed
            cost = 300 # Base daily cost
            trend = 0
            if "high" in c.threat_level.lower():
                cost += 50
                trend = 12
            elif "critical" in c.threat_level.lower():
                cost += 100
                trend = 25
            
            agent_costs.append({
                "agentName": c.name,
                "cost": cost,
                "trend": trend
            })
    
    # Sort by cost desc
    agent_costs.sort(key=lambda x: x['cost'], reverse=True)

    return {
        "totalSpend": projected_monthly,
        "totalSaved": total_saved,
        "savingsPercent": int((stopped_count / (active_count + stopped_count + 0.001)) * 100),
        "burnRate": int(daily_burn),
        "projectedMonthly": int(projected_monthly),
        "agentCosts": agent_costs
    }
