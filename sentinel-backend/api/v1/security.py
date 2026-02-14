from fastapi import APIRouter
from typing import List
from pydantic import BaseModel
from core.scanner import DockerScanner

router = APIRouter()

# Global scanner instance to maintain connection (or access singleton)
scanner = DockerScanner.get_instance()

class SecurityAlert(BaseModel):
    id: str
    severity: str
    message: str
    agentName: str
    timestamp: str

@router.get("/security/alerts", response_model=List[SecurityAlert])
async def get_alerts():
    """
    Get all security alerts.
    Implementation: Get the list of containers from the scanner. For EVERY container found, manually create a SecurityAlert object.
    """
    containers = scanner.scan_containers()
    
    alerts = []
    
    for i, container in enumerate(containers):
        # Schema Requirement: It MUST look like this
        alert = SecurityAlert(
            id=f"alert_{i+1}",
            severity="medium",
            message="Shadow AI Activity Detected",
            agentName=container.name,
            timestamp="2026-02-14T20:30:00"
        )
        alerts.append(alert)
            
    return alerts
