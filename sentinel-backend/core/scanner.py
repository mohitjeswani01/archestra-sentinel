import docker
import sys
import logging
import time
import threading
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# GLOBAL CACHE
DOCKER_CACHE = {
    "containers": [],
    "timestamp": 0
}

class ContainerInfo(BaseModel):
    id: str
    name: str
    image: str
    status: str
    is_sanctioned: bool
    type: str = "mcp_server"
    threat_level: str
    risk_score: int
    trust_score: int
    trust_details: Optional[Dict[str, Any]] = None

class DockerScanner:
    _instance = None
    _background_thread = None
    _stop_event = threading.Event()

    def __init__(self):
        pass

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = DockerScanner()
        return cls._instance

    def _connect(self):
        try:
            client = docker.DockerClient(base_url="tcp://host.docker.internal:2375", timeout=10)
            client.ping()
            return client
        except:
            pass
        
        try:
            client = docker.from_env(timeout=10)
            client.ping()
            return client
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            return None

    def _get_container_stats_safe(self, container) -> Dict[str, Any]:
        try:
            return container.stats(stream=False)
        except:
            return {}

    def _perform_scan(self):
        global DOCKER_CACHE
        
        client = self._connect()
        if not client:
            return

        try:
            containers = client.containers.list(all=True)
        except:
            return

        results = []
        from core.risk_engine import TrustScoreEvaluator, SANCTIONED_IMAGES

        for container in containers:
            try:
                name = container.name or ""
                # Handle Image name parsing safely
                try:
                    image_tags = container.image.tags if container.image.tags else [str(container.image)]
                    image_name = image_tags[0] if image_tags else "unknown"
                except:
                    image_name = "unknown"
                    
                image_repo = image_name.split(":")[0]

                is_sanctioned = any(s in image_repo.lower() for s in SANCTIONED_IMAGES)
                
                # Fetch Stats
                stats = self._get_container_stats_safe(container)

                # CALCULATE TRUST SCORE
                try:
                    trust_score, trust_details = TrustScoreEvaluator.calculate_trust_score(
                        container.attrs, image_name, stats
                    )
                except Exception as e:
                    logger.error(f"Trust calc failed for {name}: {e}")
                    trust_score = 50
                    trust_details = {"error": "calculation_failed"}

                if trust_score >= 80: threat_level = "Low"
                elif trust_score >= 60: threat_level = "Medium"
                elif trust_score >= 40: threat_level = "High"
                else: threat_level = "Critical"

                if not is_sanctioned and trust_score < 60:
                    threat_level = "Critical"
                
                # Determine type
                ctype = "mcp_server"
                try:
                    name_lower = name.lower()
                    image_lower = image_name.lower()
                    agent_keywords = ['agent', 'ai', 'bot', 'sentinel', 'orchestrate', 'llm', 'gpt']
                    if any(k in name_lower for k in agent_keywords) or any(k in image_lower for k in agent_keywords):
                        ctype = "ai_agent"
                except:
                    pass

                info = ContainerInfo(
                    id=container.short_id,
                    name=name,
                    image=image_name,
                    status=container.status,
                    is_sanctioned=is_sanctioned,
                    type=ctype,
                    threat_level=threat_level,
                    risk_score=100 - trust_score,
                    trust_score=trust_score,
                    trust_details=trust_details,
                )
                results.append(info)

            except Exception as e:
                logger.error(f"Error processing container {container.name}: {e}")
                continue
        
        # ATOMIC UPDATE
        DOCKER_CACHE["containers"] = results
        DOCKER_CACHE["timestamp"] = time.time()
        logger.info(f"Background Scan Complete. Cached {len(results)} containers.")
        
        try:
            client.close()
        except:
            pass

    def scan_containers(self) -> List[ContainerInfo]:
        global DOCKER_CACHE
        if not DOCKER_CACHE["containers"] and DOCKER_CACHE["timestamp"] == 0:
            logger.info("Cache empty, performing initial synchronous scan...")
            self._perform_scan()
            
        return DOCKER_CACHE["containers"]

def start_background_scanning():
    """Starts the background thread"""
    scanner = DockerScanner.get_instance()
    
    def loop():
        while not scanner._stop_event.is_set():
            try:
                scanner._perform_scan()
            except Exception as e:
                logger.error(f"Background scan error: {e}")
            time.sleep(30)
            
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return thread
