from typing import Dict, Any

def calculate_risk_score(container_attrs: Dict[str, Any], image_tags: list) -> int:
    """
    Calculates a risk score (0-100) based on container metadata.
    
    Factors:
    - Root user (if detectable via Config.User): +30
    - Privileged mode (HostConfig.Privileged): +40
    - Exposed critical ports (22, 2375): +20
    - No healthcheck (Config.Healthcheck): +10
    - Image from untrusted registry (no '.' in first part or known public): +15 (simplified)
    """
    score = 0
    
    # 1. Privileged Mode
    host_config = container_attrs.get("HostConfig", {})
    if host_config.get("Privileged"):
        score += 40

    # 2. Root User (Default is often root if User is empty string)
    # We'll assume empty string implies root for many images, or check explicitly
    config = container_attrs.get("Config", {})
    user = config.get("User", "")
    if user == "" or user == "0" or user == "root":
        score += 30

    # 3. Critical Ports
    # NetworkSettings.Ports is dict of "port/proto" -> list of bindings or None
    network_settings = container_attrs.get("NetworkSettings", {})
    ports = network_settings.get("Ports", {})
    
    critical_ports = ["22/tcp", "2375/tcp", "23/tcp"]
    for cp in critical_ports:
        if cp in ports:
            score += 20
            break

    # 4. No Healthcheck
    if "Healthcheck" not in config:
        score += 10

    # 5. Untrusted Image (Heuristic)
    # If image doesn't look like myregistry.com/image, might be public/untrusted
    # Simple check: if no dot in the first segment before slash, it's likely Docker Hub library or user
    if image_tags:
        image_name = image_tags[0]
        if "/" not in image_name or "." not in image_name.split("/")[0]:
             score += 15

    return min(score, 100)
