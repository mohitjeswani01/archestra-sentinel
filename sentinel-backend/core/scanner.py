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
    threat_level: str
    risk_score: int
    trust_score: int
    trust_details: Optional[Dict[str, Any]] = None

class DockerScanner:
    def __init__(self):
        try:
            # Try environment first (Linux/Mac with docker socket)
            self.client = docker.from_env()
        except Exception as e:
            # Try Windows TCP connection to Docker Desktop
            try:
                logger.warning(f"Docker from_env failed: {e}. Trying Windows TCP...")
                self.client = docker.DockerClient(base_url="tcp://127.0.0.1:2375")
                # Test connection
                self.client.ping()
                logger.info("Connected via Windows TCP (127.0.0.1:2375)")
            except Exception as e2:
                logger.error(f"CRITICAL: Could not connect to Docker. Error: {e}, Error2: {e2}")
                self.client = None

    def _get_container_stats_safe(self, container) -> Dict[str, Any]:
        """
        Safely get container stats with error handling
        """
        try:
            stats = container.stats(stream=False)
            return stats
        except Exception as e:
            logger.warning(f"Could not get stats for container {container.name}: {e}")
            return {}

    def scan_containers(self) -> List[ContainerInfo]:
        if not self.client:
            logger.warning("Docker client is not initialized. returning empty list.")
            return []

        try:
            containers = self.client.containers.list(all=True)
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return []

        results = []
        from core.risk_engine import TrustScoreEvaluator, SANCTIONED_IMAGES

        for container in containers:
            try:
                name = container.name or ""
                image_tags = container.image.tags if container.image.tags else [str(container.image)]
                image_name = image_tags[0] if image_tags else "unknown"
                image_repo = image_name.split(":")[0]

                # Check if sanctioned
                is_sanctioned = any(
                    sanctioned in image_repo.lower() for sanctioned in SANCTIONED_IMAGES
                )

                # Get container stats for Resource Footprint calculation
                stats = self._get_container_stats_safe(container)

                # Calculate new Trust Score
                try:
                    trust_score, trust_details = TrustScoreEvaluator.calculate_trust_score(
                        container.attrs, image_name, stats
                    )
                except Exception as e:
                    logger.error(f"Error calculating trust score for {name}: {e}")
                    trust_score = 50
                    trust_details = {"error": str(e)}

                # Convert trust score to risk score (inverse) for backward compatibility
                risk_score = 100 - trust_score

                # Determine Threat Level based on trust score (not risk score)
                if trust_score >= 80:
                    threat_level = "Low"
                elif trust_score >= 60:
                    threat_level = "Medium"
                elif trust_score >= 40:
                    threat_level = "High"
                else:
                    threat_level = "Critical"

                # Additional flag: if not sanctioned, elevate threat
                if not is_sanctioned and trust_score < 60:
                    threat_level = "Critical"

                info = ContainerInfo(
                    id=container.short_id,
                    name=name,
                    image=image_name,
                    status=container.status,
                    is_sanctioned=is_sanctioned,
                    threat_level=threat_level,
                    risk_score=risk_score,
                    trust_score=trust_score,
                    trust_details=trust_details,
                )
                results.append(info)

            except Exception as e:
                logger.error(f"Error processing container: {e}")
                continue

        return results
