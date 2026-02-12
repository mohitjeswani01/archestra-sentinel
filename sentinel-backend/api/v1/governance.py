from fastapi import APIRouter, HTTPException, BackgroundTasks
import docker
from pydantic import BaseModel
from typing import List
from core.event_logger import logger

router = APIRouter()

class GovernanceActionResponse(BaseModel):
    success: bool
    message: str
    container_id: str

@router.post("/governance/terminate/{container_id}")
async def terminate_container(container_id: str):
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        name = container.name
        
        # Kill and Remove
        container.kill()
        container.remove(force=True)
        
        logger.log(name, "Terminate", "Success", f"Container {container_id} terminated via governance policy.")
        
        return {
            "success": True, 
            "message": f"Container {container_id} terminated and removed.",
            "container_id": container_id
        }
    except docker.errors.NotFound:
        logger.log(container_id, "Terminate", "Failed", "Container not found.")
        raise HTTPException(status_code=404, detail=f"Container {container_id} not found")
    except Exception as e:
        logger.log(container_id, "Terminate", "Failed", str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/governance/quarantine/{container_id}")
async def quarantine_container(container_id: str):
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        name = container.name
        
        # Pause the container as a quarantine measure
        container.pause()
        
        logger.log(name, "Quarantine", "Success", f"Container {container_id} quarantined (paused).")
        
        return {
            "success": True, 
            "message": f"Container {container_id} quarantined (paused).",
            "container_id": container_id
        }
    except docker.errors.NotFound:
         logger.log(container_id, "Quarantine", "Failed", "Container not found.")
         raise HTTPException(status_code=404, detail=f"Container {container_id} not found")
    except Exception as e:
        # Check if already paused
        if "is already paused" in str(e):
             logger.log(container_id, "Quarantine", "Warning", "Container was already paused.")
             return {
                "success": True, 
                "message": f"Container {container_id} was already quarantined.",
                "container_id": container_id
            }
        logger.log(container_id, "Quarantine", "Failed", str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/governance/audit-logs")
async def get_audit_logs():
    return logger.get_logs()
