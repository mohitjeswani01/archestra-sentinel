from datetime import datetime
from typing import List, Dict

class InMemoryLogger:
    _instance = None
    _logs: List[Dict] = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(InMemoryLogger, cls).__new__(cls)
            cls._instance.log("System", "Archestra Sentinel", "Startup", "System Initialized")
        return cls._instance

    def log(self, agent: str, action: str, status: str, details: str):
        entry = {
            "id": f"evt_{len(self._logs) + 1}_{datetime.now().timestamp()}",
            "timestamp": datetime.now().isoformat(),
            "agentName": agent,
            "action": action,
            "status": status,
            "details": details,
            "tool": "Docker SDK", # Default for now
            "duration": 0 # Default
        }
        # Prepend to keep newest first
        self._logs.insert(0, entry)
        # Keep only last 50
        if len(self._logs) > 50:
            self._logs.pop()

    def get_logs(self) -> List[Dict]:
        return self._logs

logger = InMemoryLogger()
