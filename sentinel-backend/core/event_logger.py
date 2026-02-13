from datetime import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel
import logging

# Don't name this 'logger' to avoid conflicts with InMemoryLogger
_python_logger = logging.getLogger(__name__)


class AuditLogEntry(BaseModel):
    """Structured audit log entry"""
    id: str
    timestamp: str
    agent_name: str
    action: str
    status: str
    details: str
    tool: str = "Docker SDK"
    duration: int = 0
    container_id: Optional[str] = None
    trust_score_change: Optional[Dict[str, int]] = None  # {before, after}


class InMemoryLogger:
    """
    In-memory audit logger with singleton pattern.
    Tracks container actions and trust score changes.
    """
    _instance = None
    _logs: List[Dict] = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(InMemoryLogger, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize with startup event"""
        self.log("System", "Archestra Sentinel", "Startup", "System Initialized")

    def log(
        self,
        agent: str,
        action: str,
        status: str,
        details: str,
        tool: str = "Docker SDK",
        duration: int = 0,
        container_id: Optional[str] = None,
        trust_score_change: Optional[Dict[str, int]] = None,
    ):
        """
        Log an event with full context
        
        Args:
            agent: Container/agent name
            action: Action taken (Terminate, Quarantine, Scan, etc.)
            status: Success, Warning, Failed
            details: Detailed message
            tool: Tool used (Docker SDK, etc.)
            duration: Duration in ms
            container_id: Container ID if applicable
            trust_score_change: {before: score1, after: score2}
        """
        try:
            entry = {
                "id": f"evt_{len(self._logs) + 1}_{int(datetime.now().timestamp() * 1000)}",
                "timestamp": datetime.now().isoformat(),
                "agentName": agent,
                "action": action,
                "status": status,
                "details": details,
                "tool": tool,
                "duration": duration,
                "container_id": container_id,
                "trust_score_change": trust_score_change,
            }
            
            # Prepend to keep newest first
            self._logs.insert(0, entry)
            
            # Keep only last 100 entries for memory efficiency
            if len(self._logs) > 100:
                self._logs.pop()
            
            _python_logger.debug(f"Logged event: {action} for {agent}")

        except Exception as e:
            _python_logger.error(f"Error logging event: {e}")

    def get_logs(self) -> List[Dict]:
        """Get all logs (newest first)"""
        return self._logs

    def get_logs_by_container(self, container_id: str) -> List[Dict]:
        """Get logs for specific container"""
        return [log for log in self._logs if log.get("container_id") == container_id]

    def get_logs_by_action(self, action: str) -> List[Dict]:
        """Get logs for specific action type"""
        return [log for log in self._logs if log.get("action") == action]

    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent logs (newest first)"""
        return self._logs[:limit]

    def clear_logs(self):
        """Clear all logs (for testing)"""
        self._logs = []


# Global logger instance
logger_instance = InMemoryLogger()


# Convenience functions
def log(agent: str, action: str, status: str, details: str, **kwargs):
    """Log event using global logger"""
    logger_instance.log(agent, action, status, details, **kwargs)


def get_logs() -> List[Dict]:
    """Get all logs"""
    return logger_instance.get_logs()


def log_trust_score_change(
    container_name: str,
    container_id: str,
    old_score: int,
    new_score: int,
    reason: str = "Scan update",
):
    """Log a trust score change event"""
    log(
        container_name,
        "Trust Score Updated",
        "Success",
        f"{reason}. Old: {old_score}, New: {new_score}",
        container_id=container_id,
        trust_score_change={"before": old_score, "after": new_score},
    )
