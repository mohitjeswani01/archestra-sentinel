import docker
from typing import List, Dict, Any
from pydantic import BaseModel

class ContainerInfo(BaseModel):
    id: str
    name: str
    image: str
    status: str
    is_sanctioned: bool
    threat_level: str

class DockerScanner:
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            print(f"Error connecting to Docker: {e}")
            self.client = None

    def scan_containers(self) -> List[ContainerInfo]:
        if not self.client:
            return []

        containers = self.client.containers.list(all=True)
        results = []

        for container in containers:
            is_sanctioned = False
            threat_level = "High"
            
            # Logic: If a container name or image string DOES NOT contain "archestra", flag it.
            # Convert to string to be safe, though they should be strings.
            name = container.name or ""
            # image tags is a list, we check if any tag contains "archestra" or if the image object string does.
            image_tags = container.image.tags if container.image.tags else [str(container.image)]
            image_str = str(image_tags)

            if "archestra" in name.lower() or "archestra" in image_str.lower():
                is_sanctioned = True
                threat_level = "Low"

            info = ContainerInfo(
                id=container.short_id,
                name=name,
                image=image_tags[0] if image_tags else "unknown",
                status=container.status,
                is_sanctioned=is_sanctioned,
                threat_level=threat_level
            )
            results.append(info)

        return results
