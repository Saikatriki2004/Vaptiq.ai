"""
Resilient Celery Worker with Redis Integration
"""
import asyncio
import redis
import os
from celery.exceptions import SoftTimeLimitExceeded
from celery_config import celery_app
from agent import SecurityAgent
from models import ScanTarget
from db_logger import DatabaseLogger

# Initialize Redis for the worker to read flags
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))


@celery_app.task(
    bind=True,
    name="scan.run_agentic_scan",
    acks_late=True,          # Don't acknowledge until done (resilience)
    retry_backoff=True,      # Exponential backoff if Redis fails
    max_retries=3
)
def run_background_scan(self, target_data: dict, scan_id: str):
    """
    Background Task: Instantiates the Agent and runs the full VAPT loop.
    
    Args:
        target_data: Dictionary containing target information
        scan_id: Unique identifier for the scan
        
    Returns:
        Dictionary with scan results
    """
    logger = DatabaseLogger(scan_id)
    
    try:
        logger.log("SYSTEM", f"Job picked up by worker {self.request.id}")
        logger.update_status("RUNNING")
        
        # Reconstruct the Target object
        target = ScanTarget(**target_data)
        
        # Initialize Agent with Context (including Redis client for cancellation)
        agent = SecurityAgent(target, scan_id, redis_client)
        
        # Run the Async Logic properly using asyncio.run()
        result = asyncio.run(agent.execute())
        
        # Save results to Redis
        logger.save_vulnerabilities(result.get("vulnerabilities", []))
        
        # Log completion
        logger.log("SYSTEM", "Scan completed successfully.")
        logger.update_status("COMPLETED")
        
        return {"status": "OK", "scan_id": scan_id}
        
    except SoftTimeLimitExceeded:
        # Graceful shutdown if scan takes too long
        logger.log("SYSTEM", "Time limit exceeded. Gracefully stopping tools...")
        logger.update_phase("TIMEOUT")
        logger.update_status("TIMEOUT")
        return {"status": "TIMEOUT", "scan_id": scan_id}
        
    except Exception as e:
        # Handle crashes with retry mechanism
        logger.log("FATAL", f"Worker Error: {str(e)}")
        logger.update_phase("FAILED")
        logger.update_status("FAILED")
        
        # Retry the task
        raise self.retry(exc=e)
