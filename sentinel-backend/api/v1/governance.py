from fastapi import APIRouter, HTTPException, BackgroundTasks
import docker
from pydantic import BaseModel
from typing import List, Optional, Any
from core.event_logger import log, log_trust_score_change
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


class GovernanceActionResponse(BaseModel):
    """Response from governance action"""
    success: bool
    message: str
    container_id: str
    action_taken: str


class AuditLogResponse(BaseModel):
    """Audit log entry response"""
    id: str
    timestamp: str
    agent_name: str
    action: str
    status: str
    details: str
    tool: str
    duration: int
    container_id: Optional[str] = None
    trust_score_change: Optional[Any] = None # Relaxed type to avoid 422


def get_docker_client():
    """
    Get Docker client with Windows TCP fallback support
    """
    try:
        # Try environment first (Linux/Mac)
        client = docker.from_env()
        return client
    except Exception as e:
        logger.warning(f"docker.from_env() failed: {e}")
        try:
            # Try Windows TCP connection
            client = docker.DockerClient(base_url="tcp://127.0.0.1:2375")
            client.ping()
            logger.info("Using Windows TCP connection (127.0.0.1:2375)")
            return client
        except Exception as e2:
            logger.error(f"Failed to connect to Docker: {e}, {e2}")
            raise


@router.post("/governance/terminate/{container_id}", response_model=GovernanceActionResponse)
async def terminate_container(container_id: str):
    """
    Terminate and remove a container (high-risk governance action)
    """
    try:
        client = get_docker_client()
    except Exception as e:
        logger.error(f"Docker connection failed: {e}")
        raise HTTPException(status_code=503, detail="Docker service unavailable")

    try:
        container = client.containers.get(container_id)
        name = container.name
        old_trust_score = None

        # Get current trust score from attrs if available (for logging)
        try:
            from core.scanner import DockerScanner
            scanner = DockerScanner()
            containers_info = scanner.scan_containers()
            for c in containers_info:
                if c.id.startswith(container_id[:12]):
                    old_trust_score = c.trust_score
                    break
        except Exception as e:
            logger.warning(f"Could not get trust score: {e}")

        # Kill and Remove with error handling
        try:
            container.kill()
            logger.debug(f"Container {name} killed")
        except Exception as e:
            if "is not running" in str(e):
                logger.info(f"Container {name} was not running")
            else:
                raise

        try:
            container.remove(force=True)
            logger.debug(f"Container {name} removed")
        except Exception as e:
            logger.warning(f"Error removing container {name}: {e}")

        # Log the action with trust score context
        log(
            name,
            "Terminate",
            "Success",
            f"Container {container_id} terminated via governance policy",
            container_id=container_id,
            tool="Governor Enforcement",
        )

        if old_trust_score is not None:
            log_trust_score_change(
                name,
                container_id,
                old_trust_score,
                0,
                "Container terminated",
            )

        return GovernanceActionResponse(
            success=True,
            message=f"Container {name} ({container_id}) terminated and removed",
            container_id=container_id,
            action_taken="terminate",
        )

    except docker.errors.NotFound:
        logger.warning(f"Container {container_id} not found")
        log(
            container_id,
            "Terminate",
            "Failed",
            "Container not found",
            container_id=container_id,
        )
        raise HTTPException(status_code=404, detail=f"Container {container_id} not found")

    except Exception as e:
        logger.error(f"Error terminating container {container_id}: {e}")
        log(
            container_id,
            "Terminate",
            "Failed",
            str(e),
            container_id=container_id,
        )
        raise HTTPException(status_code=500, detail=f"Failed to terminate container: {str(e)}")


@router.post("/governance/quarantine/{container_id}", response_model=GovernanceActionResponse)
async def quarantine_container(container_id: str):
    """
    Quarantine a container by pausing it (investigative governance action)
    """
    try:
        client = get_docker_client()
    except Exception as e:
        logger.error(f"Docker connection failed: {e}")
        raise HTTPException(status_code=503, detail="Docker service unavailable")

    try:
        container = client.containers.get(container_id)
        name = container.name
        old_trust_score = None

        # Get current trust score (for logging)
        try:
            from core.scanner import DockerScanner
            scanner = DockerScanner()
            containers_info = scanner.scan_containers()
            for c in containers_info:
                if c.id.startswith(container_id[:12]):
                    old_trust_score = c.trust_score
                    break
        except Exception as e:
            logger.warning(f"Could not get trust score: {e}")

        # Pause the container (quarantine)
        try:
            container.pause()
            logger.info(f"Container {name} quarantined (paused)")

            log(
                name,
                "Quarantine",
                "Success",
                f"Container {container_id} quarantined (paused) for investigation",
                container_id=container_id,
                tool="Governor Enforcement",
            )

            if old_trust_score is not None:
                log_trust_score_change(
                    name,
                    container_id,
                    old_trust_score,
                    max(old_trust_score - 10, 0),  # Penalize by 10 points
                    "Container quarantined",
                )

            return GovernanceActionResponse(
                success=True,
                message=f"Container {name} ({container_id}) quarantined (paused)",
                container_id=container_id,
                action_taken="quarantine",
            )

        except docker.errors.APIError as e:
            if "already paused" in str(e):
                logger.info(f"Container {name} was already paused")
                log(
                    name,
                    "Quarantine",
                    "Warning",
                    "Container was already quarantined",
                    container_id=container_id,
                )
                return GovernanceActionResponse(
                    success=True,
                    message=f"Container {name} was already quarantined",
                    container_id=container_id,
                    action_taken="quarantine",
                )
            else:
                raise

    except docker.errors.NotFound:
        logger.warning(f"Container {container_id} not found")
        log(
            container_id,
            "Quarantine",
            "Failed",
            "Container not found",
            container_id=container_id,
        )
        raise HTTPException(status_code=404, detail=f"Container {container_id} not found")

    except Exception as e:
        logger.error(f"Error quarantining container {container_id}: {e}")
        log(
            container_id,
            "Quarantine",
            "Failed",
            str(e),
            container_id=container_id,
        )
        raise HTTPException(status_code=500, detail=f"Failed to quarantine container: {str(e)}")


@router.get("/governance/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(limit: int = 50):
    """
    Get audit logs with full trust score context
    Supports pagination via limit parameter
    """
    try:
        from core.event_logger import get_logs

        all_logs = get_logs()
        recent_logs = all_logs[:limit]
        
        valid_logs = []
        for log_entry in recent_logs:
            try:
                # Ensure all required fields exist or have defaults
                valid_logs.append(AuditLogResponse(
                    id=str(log_entry.get("id", "")),
                    timestamp=str(log_entry.get("timestamp", "")),
                    agent_name=str(log_entry.get("agentName", "Unknown")),
                    action=str(log_entry.get("action", "Unknown")),
                    status=str(log_entry.get("status", "Info")),
                    details=str(log_entry.get("details", "")),
                    tool=str(log_entry.get("tool", "Docker SDK")),
                    duration=int(log_entry.get("duration", 0)),
                    container_id=log_entry.get("container_id"),
                    trust_score_change=log_entry.get("trust_score_change"),
                ))
            except Exception as e:
                logger.warning(f"Skipping malformed log entry: {e}")
                continue

        return valid_logs

    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        return []
