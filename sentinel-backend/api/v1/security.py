from fastapi import APIRouter
from typing import List
from pydantic import BaseModel
from core.scanner import DockerScanner

router = APIRouter()

class SecurityAlert(BaseModel):
    id: str
    severity: str
    agentId: str
    agentName: str
    violationType: str
    description: str
    timestamp: str
    status: str

@router.get("/security/alerts", response_model=List[SecurityAlert])
async def get_security_alerts():
    scanner = DockerScanner()
    containers = scanner.scan_containers()
    alerts = []
    
    from datetime import datetime

    count = 1
    for c in containers:
        # User Rule: "Shadow AI" or High Risk generates alert
        if c.risk_score > 70 or not c.is_sanctioned:
            severity = "critical" if c.risk_score >= 80 else "high"
            violation = "High Risk Container"
            desc = f"Container {c.name} has a risk score of {c.risk_score}."
            
            if not c.is_sanctioned:
                 severity = "critical"
                 violation = "Shadow AI Detected"
                 desc = f"Unauthorized Container {c.name} detected on host. Origin: {c.image}"

            alerts.append(SecurityAlert(
                id=f"alert-{c.id[:8]}-{count}",
                severity=severity,
                agentId=c.id,
                agentName=c.name,
                violationType=violation,
                description=desc,
                timestamp=datetime.now().isoformat(),
                status="active"
            ))
            count += 1
            
    return alerts
