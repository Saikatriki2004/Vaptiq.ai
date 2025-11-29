"""
Resilient Celery Worker with Redis Integration and Credit Refund Logic
"""
import asyncio
import redis
import os
from celery.exceptions import SoftTimeLimitExceeded
from .celery_config import celery_app
from .agent import SecurityAgent
from .models import ScanTarget
from .db_logger import DatabaseLogger
from .db import db

# Initialize Redis for the worker to read flags
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))


async def _refund_user(user_id: str, amount: int, scan_id: str, reason: str):
    """
    Atomically refund credits and log transaction.
    
    This function is critical for preventing user churn from system failures.
    Without refunds, users lose credits every time:
    - Celery worker crashes (OOM kill)
    - Network timeout occurs
    - LLM API is down
    - Target server is unreachable
    
    Args:
        user_id: User to refund
        amount: Number of credits to refund
        scan_id: Scan that failed
        reason: Explanation for refund
    """
    await db.user.update(
        where={"id": user_id},
        data={"credits": {"increment": amount}}
    )
    
    await db.credittransaction.create(data={
        "userId": user_id,
        "amount": amount,
        "type": "SCAN_REFUND_ERROR",
        "scanId": scan_id,
        "reason": reason
    })
    
    print(f"✅ Refunded {amount} credits to user {user_id[:8]}... (Reason: {reason})")


@celery_app.task(
    bind=True,
    name="scan.run_agentic_scan",
    acks_late=True,          # Don't acknowledge until done (resilience)
    retry_backoff=True,      # Exponential backoff if Redis fails
    max_retries=3
)
def run_background_scan(self, target_data: dict, scan_id: str, user_id: str):
    """
    Background Task: Instantiates the Agent and runs the full VAPT loop.
    
    Args:
        target_data: Dictionary containing target information
        scan_id: Unique identifier for the scan
        user_id: User ID for refund purposes (CRITICAL for bankruptcy prevention)
        
    Returns:
        Dictionary with scan results
    """
    logger = DatabaseLogger(scan_id)
    cost = 0 if target_data.get("dry_run") else 10
    
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
        logger.log("SYSTEM", "Time limit exceeded. Refunding user...")
        logger.update_phase("TIMEOUT")
        logger.update_status("TIMEOUT")
        
        # REFUND LOGIC (Timeout)
        if cost > 0:
            asyncio.run(_refund_user(user_id, cost, scan_id, "TIMEOUT - Scan exceeded 30-minute limit"))
        
        return {"status": "TIMEOUT", "scan_id": scan_id}
        
    except Exception as e:
        # Handle crashes with refund and retry mechanism
        logger.log("FATAL", f"Worker Error: {str(e)}")
        logger.update_phase("FAILED")
        logger.update_status("FAILED")
        
        # REFUND LOGIC (Error)
        if cost > 0:
            error_msg = str(e)[:100]  # Truncate long errors
            asyncio.run(_refund_user(user_id, cost, scan_id, f"ERROR: {error_msg}"))
        
        # Retry the task
        raise self.retry(exc=e)
