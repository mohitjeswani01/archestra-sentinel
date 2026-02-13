import docker
from typing import Dict, Any, List, Tuple
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Whitelist of sanctioned images (CRITICAL SECURITY)
SANCTIONED_IMAGES = [
    "archestra/platform",
    "postgres",
    "sentinel-backend",
    "sentinel-frontend",
]

# Ports considered safe (if bound to localhost only)
SAFE_BIND_IPS = ["127.0.0.1", "localhost", "::1"]
CRITICAL_PORTS_INTERNAL = [2375, 2376, 22, 23, 6379, 5432, 3306, 27017]


class TrustScoreEvaluator:
    """
    Deep Trust Intelligence Engine - Calculates Trust Score (0-100) for containers
    
    4 Weighted Vectors:
    - V1: Identity (30%): Sanctioned image check
    - V2: Configuration (30%): Root/Privileged/ReadOnlyRootfs
    - V3: Network Exposure (20%): Port bindings to 0.0.0.0
    - V4: Resource Footprint (20%): CPU/Memory limits
    """

    @staticmethod
    def _evaluate_identity(image_name: str) -> Tuple[int, str]:
        """
        V1: Identity Vector (30% weight)
        Checks if image is in sanctioned list or verified repository
        Returns: (score_0_100, explanation)
        """
        score = 0
        explanation = "Identity: "

        # Extract image repo from full image name
        image_repo = image_name.split(":")[0] if image_name else ""
        
        # Check against whitelist
        is_sanctioned = any(
            sanctioned in image_repo.lower() for sanctioned in SANCTIONED_IMAGES
        )
        
        if is_sanctioned:
            score = 100
            explanation += f"✓ Sanctioned image ({image_repo})"
        elif "." in image_repo.split("/")[0] if "/" in image_repo else False:
            # Has registry (domain), likely private/verified
            score = 80
            explanation += f"✓ Private registry detected ({image_repo})"
        elif "/" in image_repo:
            # Has org/user namespace (e.g., myorg/image)
            score = 60
            explanation += f"⚠ Public namespace image ({image_repo})"
        else:
            # Unknown or Docker Hub library (potential Shadow AI)
            score = 20
            explanation += f"✗ Unverified/Shadow AI ({image_repo})"
        
        return score, explanation

    @staticmethod
    def _evaluate_configuration(container_attrs: Dict[str, Any]) -> Tuple[int, str]:
        """
        V2: Configuration Vector (30% weight)
        Checks: root user, privileged mode, ReadOnlyRootfs
        Returns: (score_0_100, explanation)
        """
        score = 100  # Start perfect, deduct for issues
        explanation = "Config: "
        issues = []

        host_config = container_attrs.get("HostConfig", {})
        config = container_attrs.get("Config", {})

        # Check 1: Root User
        user = config.get("User", "")
        if user == "" or user == "0" or user == "root":
            score -= 30
            issues.append("ROOT_USER")
        
        # Check 2: Privileged Mode
        if host_config.get("Privileged"):
            score -= 35
            issues.append("PRIVILEGED_MODE")
        
        # Check 3: ReadOnlyRootfs (absence is a risk)
        if not host_config.get("ReadonlyRootfs"):
            score -= 20
            issues.append("WRITABLE_ROOT_FS")
        
        # Check 4: Cap Drop (best practice)
        if not host_config.get("CapDrop"):
            score -= 10
            issues.append("NO_CAP_DROP")

        if issues:
            explanation += f"✗ Issues: {', '.join(issues)}"
        else:
            explanation += "✓ Secure configuration"
        
        return max(score, 0), explanation

    @staticmethod
    def _evaluate_network_exposure(container_attrs: Dict[str, Any]) -> Tuple[int, str]:
        """
        V3: Network Exposure Vector (20% weight)
        Checks port bindings: 0.0.0.0 = HIGH RISK, 127.0.0.1 = SAFE
        Returns: (score_0_100, explanation)
        """
        score = 100  # Start perfect
        explanation = "Network: "
        risks = []

        # Method 1: HostConfig.PortBindings (more reliable)
        port_bindings = container_attrs.get("HostConfig", {}).get("PortBindings", {})
        
        if port_bindings:
            for port_spec, bindings_list in port_bindings.items():
                if bindings_list:
                    for binding in bindings_list:
                        host_ip = binding.get("HostIp", "")
                        host_port = binding.get("HostPort", "")
                        
                        # Extract port number
                        port_num = None
                        try:
                            port_num = int(port_spec.split("/")[0])
                        except:
                            pass
                        
                        # Check for 0.0.0.0 binding (world-accessible)
                        if host_ip == "0.0.0.0" or host_ip == "":
                            if port_num in CRITICAL_PORTS_INTERNAL:
                                score -= 40
                                risks.append(f"CRITICAL:{port_num}/world")
                            else:
                                score -= 20
                                risks.append(f"EXPOSED:{port_num}")
                        # Check for safe binding
                        elif host_ip not in SAFE_BIND_IPS:
                            score -= 5
                            risks.append(f"NON_LOCAL:{host_ip}:{port_num}")
        
        # Method 2: NetworkSettings.Ports (fallback)
        if not port_bindings:
            ports = container_attrs.get("NetworkSettings", {}).get("Ports", {})
            if ports:
                for port_spec, bindings in ports.items():
                    if bindings:
                        for binding in bindings:
                            if binding.get("HostIp") == "0.0.0.0":
                                score -= 25
                                risks.append(f"BINDING:{port_spec}/0.0.0.0")

        if risks:
            explanation += f"✗ Exposed: {', '.join(risks[:2])}"  # Show first 2
        else:
            explanation += "✓ No public port exposure"
        
        return max(score, 0), explanation

    @staticmethod
    def _evaluate_resource_footprint(container_stats: Dict[str, Any]) -> Tuple[int, str]:
        """
        V4: Resource Footprint Vector (20% weight)
        Checks CPU/Memory limits and actual usage
        Returns: (score_0_100, explanation)
        """
        score = 100
        explanation = "Resources: "
        warnings = []

        # Extract memory limit
        memory_stats = container_stats.get("memory_stats", {})
        memory_limit = memory_stats.get("limit", 0)
        memory_usage = memory_stats.get("usage", 0)

        # Extract CPU usage
        cpu_stats = container_stats.get("cpu_stats", {})
        cpu_usage = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)

        # Check 1: No Memory Limit (8GB system default = 8589934592 bytes ≈ 8GB)
        # If memory_limit > 1GB on 8GB system, penalize as "unlimited"
        if memory_limit > (1024 * 1024 * 1024) or memory_limit == 0:  # > 1GB or 0
            score -= 25
            warnings.append(f"NO_MEMORY_LIMIT({memory_limit / 1024 / 1024 / 1024:.1f}GB)")
        
        # Check 2: Memory Usage High (> 80% of limit)
        if memory_limit > 0 and memory_usage > 0:
            usage_pct = (memory_usage / memory_limit) * 100
            if usage_pct > 80:
                score -= 15
                warnings.append(f"HIGH_MEM({usage_pct:.0f}%)")
            elif usage_pct > 50:
                score -= 5
                warnings.append(f"MED_MEM({usage_pct:.0f}%)")
        
        # Check 3: CPU Usage Detection (if > some threshold, concerning)
        if cpu_usage > (100_000_000_000):  # Rough threshold
            score -= 10
            warnings.append("HIGH_CPU")

        if warnings:
            explanation += f"⚠ {', '.join(warnings)}"
        else:
            explanation += "✓ Healthy resource profile"
        
        return max(score, 0), explanation

    @classmethod
    def calculate_trust_score(
        cls, container_attrs: Dict[str, Any], image_name: str, container_stats: Dict[str, Any] = None
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Calculate final Trust Score (0-100) with all 4 vectors
        
        Returns: (trust_score, details_dict)
        """
        if not container_stats:
            container_stats = {}

        # Calculate each vector
        identity_score, identity_detail = cls._evaluate_identity(image_name)
        config_score, config_detail = cls._evaluate_configuration(container_attrs)
        network_score, network_detail = cls._evaluate_network_exposure(container_attrs)
        resource_score, resource_detail = cls._evaluate_resource_footprint(container_stats)

        # Weighted average (30%, 30%, 20%, 20%)
        trust_score = int(
            (identity_score * 0.30)
            + (config_score * 0.30)
            + (network_score * 0.20)
            + (resource_score * 0.20)
        )

        details = {
            "trust_score": trust_score,
            "vectors": {
                "identity": {"score": identity_score, "detail": identity_detail},
                "configuration": {"score": config_score, "detail": config_detail},
                "network": {"score": network_score, "detail": network_detail},
                "resources": {"score": resource_score, "detail": resource_detail},
            },
            "timestamp": datetime.now().isoformat(),
        }

        return trust_score, details


# Backward compatibility
def calculate_risk_score(container_attrs: Dict[str, Any], image_tags: list) -> int:
    """
    Legacy function for backward compatibility
    Converts new Trust Score to old risk score format (inverted)
    """
    image_name = image_tags[0] if image_tags else "unknown"
    trust_score, _ = TrustScoreEvaluator.calculate_trust_score(container_attrs, image_name)
    
    # Convert trust score (0-100) to risk score (0-100) where high trust = low risk
    risk_score = 100 - trust_score
    return risk_score
