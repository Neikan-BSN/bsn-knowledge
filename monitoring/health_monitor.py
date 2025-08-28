# \!/usr/bin/env python3
import json
import psutil
from datetime import datetime


class HealthMonitor:
    def __init__(self):
        self.start_time = datetime.now()

    def get_status(self):
        return {
            "project": "bsn-knowledge",
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime": (datetime.now() - self.start_time).total_seconds(),
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=0.1)
                if "psutil" in globals()
                else 0,
                "memory_percent": psutil.virtual_memory().percent
                if "psutil" in globals()
                else 0,
            },
        }


if __name__ == "__main__":
    monitor = HealthMonitor()
    print(json.dumps(monitor.get_status(), indent=2))
