from fastapi import APIRouter, HTTPException
from typing import List
from core.scanner import DockerScanner, ContainerInfo
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
scanner = DockerScanner()


import asyncio

@router.get("/discovery/shadow-ai", response_model=List[ContainerInfo])
async def get_shadow_ai():
    """
    Discover containers with trust scores and identify shadow AI.
    
    Shadow AI = Unsanctioned containers with low trust scores
    """
    try:
        # Run synchronous docker calls in a thread to avoid blocking the event loop
        containers = await asyncio.to_thread(scanner.scan_containers)
        print(f"DEBUG: Found {len(containers)} containers")
        logger.info(f"Discovery API: Found {len(containers)} containers")
        return containers
    except Exception as e:
        logger.error(f"Error scanning containers: {e}")
        # Return empty list instead of 500 to avoid breaking frontend, but log heavily
        return []


@router.get("/discovery/containers", response_model=List[ContainerInfo])
async def get_all_containers():
    """
    Get all containers with full trust score details
    """
    try:
        containers = scanner.scan_containers()
        return containers
    except Exception as e:
        logger.error(f"Error getting containers: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get containers: {str(e)}")


@router.get("/discovery/containers/{container_id}", response_model=ContainerInfo)
async def get_container_details(container_id: str):
    """
    Get detailed trust score analysis for a specific container
    """
    try:
        containers = scanner.scan_containers()
        for container in containers:
            if container.id.startswith(container_id[:12]):
                return container
        raise HTTPException(status_code=404, detail=f"Container {container_id} not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting container details: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get container details: {str(e)}")
