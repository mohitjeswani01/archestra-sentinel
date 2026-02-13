import docker
import sys
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime

logger = logging.getLogger(__name__)

class ContainerInfo(BaseModel):
    id: str
    name: str
    image: str
    status: str
    is_sanctioned: bool
    type: str = "mcp_server"  # Default type: mcp_server or ai_agent
    threat_level: str
    risk_score: int
    trust_score: int
    trust_details: Optional[Dict[str, Any]] = None

class DockerScanner:
    def __init__(self):
        self.client = None
        # attempt 1: FORCE Windows/Mac TCP (host.docker.internal)
        # This is critical for Windows Docker Desktop w/ WSL2 or Hyper-V
        try:
            self.client = docker.DockerClient(base_url="tcp://host.docker.internal:2375")
            self.client.ping()
            logger.info("Connected via tcp://host.docker.internal:2375")
        except Exception as e:
            logger.warning(f"host.docker.internal failed: {e}. Attempting standard env/socket...")
            
            # attempt 2: Standard Environment
            try:
                self.client = docker.from_env()
                self.client.ping()
                logger.info("Connected to Docker via environment/socket")
            except Exception as e2:
                logger.error(f"CRITICAL: Could not connect to Docker. Error: {e2}")
                self.client = None

    def _determine_container_type(self, name: str, image: str) -> str:
        """
        Determine if a container is an 'ai_agent' or 'mcp_server'.
        """
        try:
            name_lower = name.lower() if name else ""
            image_lower = image.lower() if image else ""
            
            agent_keywords = ['agent', 'ai', 'bot', 'sentinel', 'orchestrate', 'llm', 'gpt']
            
            if any(k in name_lower for k in agent_keywords) or any(k in image_lower for k in agent_keywords):
                return "ai_agent"
        except:
            pass
            
        # Default EVERYTHING else to mcp_server so we see it in the dashboard
        return "mcp_server"

    def _get_container_stats_safe(self, container) -> Dict[str, Any]:
        try:
            # timeout=2 prevents hanging on frozen containers
            # stream=False ensures we get a snapshot, not a stream
            return container.stats(stream=False, decode=True)
        except Exception as e:
            logger.warning(f"Stats failed for {container.name}: {e}")
            # Return safe defaults to prevent crashing risk engine
            return {
                "cpu_stats": {},
                "precpu_stats": {},
                "memory_stats": {},
                "networks": {}
            }

    def scan_containers(self) -> List[ContainerInfo]:
        if not self.client:
            print("ERROR: Docker client is None. Cannot scan.")
            return []

        try:
            containers = self.client.containers.list(all=True)
            print(f"DEBUG: Scanner raw container count: {len(containers)}")
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            print(f"ERROR: Failed to list containers: {e}")
            return []

        results = []
        from core.risk_engine import TrustScoreEvaluator, SANCTIONED_IMAGES

        for container in containers:
            try:
                name = container.name or ""
                image_tags = container.image.tags if container.image.tags else [str(container.image)]
                image_name = image_tags[0] if image_tags else "unknown"
                image_repo = image_name.split(":")[0]

                is_sanctioned = any(s in image_repo.lower() for s in SANCTIONED_IMAGES)

                # Fallback stats to avoid blocking
                stats = self._get_container_stats_safe(container)

                try:
                    trust_score, trust_details = TrustScoreEvaluator.calculate_trust_score(
                        container.attrs, image_name, stats
                    )
                except:
                    trust_score = 50
                    trust_details = {"error": "calculation_failed"}

                if trust_score >= 80: threat_level = "Low"
                elif trust_score >= 60: threat_level = "Medium"
                elif trust_score >= 40: threat_level = "High"
                else: threat_level = "Critical"

                if not is_sanctioned and trust_score < 60:
                    threat_level = "Critical"
                
                # CLASSIFICATION LOGIC
                container_type = self._determine_container_type(name, image_name)

                info = ContainerInfo(
                    id=container.short_id,
                    name=name,
                    image=image_name,
                    status=container.status,
                    is_sanctioned=is_sanctioned,
                    type=container_type,
                    threat_level=threat_level,
                    risk_score=100 - trust_score,
                    trust_score=trust_score,
                    trust_details=trust_details,
                )
                results.append(info)

            except Exception as e:
                logger.error(f"Error processing container {container.name}: {e}")
                continue

        return results
