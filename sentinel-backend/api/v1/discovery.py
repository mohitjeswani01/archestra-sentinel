from fastapi import APIRouter, HTTPException
from typing import List
from core.scanner import DockerScanner, ContainerInfo

router = APIRouter()
scanner = DockerScanner()

@router.get("/discovery/shadow-ai", response_model=List[ContainerInfo])
async def get_shadow_ai():
    try:
        return scanner.scan_containers()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
