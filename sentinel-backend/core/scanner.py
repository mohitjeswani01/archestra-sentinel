import docker
import sys
from typing import List, Dict, Any
from pydantic import BaseModel

class ContainerInfo(BaseModel):
    id: str
    name: str
    image: str
    status: str
    is_sanctioned: bool
    threat_level: str
    risk_score: int

class DockerScanner:
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            import sys
            print(f"CRITICAL ERROR: Could not connect to Docker Daemon. Ensure /var/run/docker.sock is mounted. Error: {e}", file=sys.stderr)
            self.client = None

    def scan_containers(self) -> List[ContainerInfo]:
        if not self.client:
            print("WARNING: Docker client is not initialized. returning empty list.", file=sys.stderr)
            return []

        containers = self.client.containers.list(all=True)
        results = []

        from core.risk_engine import calculate_risk_score

        for container in containers:
            is_sanctioned = False
            
            # Logic: If a container name or image string DOES NOT contain "archestra", flag it.
            name = container.name or ""
            image_tags = container.image.tags if container.image.tags else [str(container.image)]
            image_str = str(image_tags)

            if "archestra" in name.lower() or "archestra" in image_str.lower():
                is_sanctioned = True
            
            # Calculate Risk Score
            # container.attrs creates a dictionary of the container's metadata
            risk_score = calculate_risk_score(container.attrs, image_tags)

            # Determine Threat Level based on score
            if risk_score >= 80:
                threat_level = "Critical"
            elif risk_score >= 50:
                threat_level = "High"
            elif risk_score >= 20:
                threat_level = "Medium"
            else:
                threat_level = "Low"
            
            # Override threat level if sanctioned (optional, but requested logic seems to imply scan checks everything)
            # Keeping calculated threat level but maybe Sanctined overrides? 
            # User requirement: "Shadow AI Detected" implies non-sanctioned. 
            # Use calculated risk for everyone, but sanctioned flag helps governance.

            info = ContainerInfo(
                id=container.short_id,
                name=name,
                image=image_tags[0] if image_tags else "unknown",
                status=container.status,
                is_sanctioned=is_sanctioned,
                threat_level=threat_level,
                risk_score=risk_score
            )
            results.append(info)

        return results
