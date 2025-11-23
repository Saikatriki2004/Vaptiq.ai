import os
import json
import redis
from datetime import datetime

class DatabaseLogger:
    """
    Logs scan events and status updates to Redis.
    This allows the API to read real-time progress from the background worker.
    """
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        # Connect to Redis
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        
    def log(self, level: str, message: str):
        """
        Append a log message to the scan's log list in Redis.
        """
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Push to the end of the list
        key = f"scan:{self.scan_id}:logs"
        self.redis_client.rpush(key, log_entry)
        
        # Set expiration (e.g., 24 hours) to prevent clutter
        self.redis_client.expire(key, 86400)
        print(log_entry) # Also print to stdout for Docker logs

    def update_status(self, status: str):
        """
        Update the scan status in Redis.
        """
        key = f"scan:{self.scan_id}:status"
        self.redis_client.set(key, status)
        self.redis_client.expire(key, 86400)
        
    def save_vulnerabilities(self, vulnerabilities: list):
        """
        Save found vulnerabilities to Redis.
        """
        key = f"scan:{self.scan_id}:vulnerabilities"
        # Serialize list of dicts to JSON string
        self.redis_client.set(key, json.dumps(vulnerabilities))
        self.redis_client.expire(key, 86400)
        
    def update_phase(self, phase: str):
        """
        Update the current scan phase (RUNNING, VERIFYING, COMPLETED, CANCELLED, FAILED, TIMEOUT).
        """
        key = f"scan:{self.scan_id}:phase"
        self.redis_client.set(key, phase)
        self.redis_client.expire(key, 86400)
        self.log("SYSTEM", f"Phase updated to: {phase}")
        
    def update_progress(self, percentage: int):
        """
        Update the scan progress percentage (0-100).
        """
        key = f"scan:{self.scan_id}:progress"
        self.redis_client.set(key, str(percentage))
        self.redis_client.expire(key, 86400)
