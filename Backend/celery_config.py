"""
Hardened Celery Configuration for Production with Stale Job Sweeper
"""
import os
import asyncio
from datetime import datetime, timedelta
from celery import Celery

# Define the Redis URL (host is 'redis' in docker network)
# Default to localhost for local testing outside docker
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Initialize Celery
celery_app = Celery(
    "sentinel_engine",  # Updated app name
    broker=REDIS_URL,
    backend=REDIS_URL
)

# Configure task serialization and resilience settings
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # --- Resilience Settings ---
    task_track_started=True,           # Track when tasks start for better monitoring
    task_time_limit=1800,              # Hard Kill after 30 mins (1800 seconds)
    task_soft_time_limit=1700,         # Throw Exception at 28 mins (allows cleanup)
    worker_concurrency=4,              # Allow 4 concurrent scans per container
    broker_connection_retry_on_startup=True,  # Retry Redis connection on startup
)

# --- Celery Beat Schedule (Periodic Tasks) ---
celery_app.conf.beat_schedule = {
    'sweep-stale-scans': {
        'task': 'sweep_stale_scans',
        'schedule': 600.0,  # Every 10 minutes (600 seconds)
    },
}


@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """
    Register periodic background jobs.
    Called automatically when Celery worker starts.
    """
    pass  # Beat schedule is already configured above


@celery_app.task(name='sweep_stale_scans')
def sweep_stale_scans():
    """
    Stale Job Sweeper: Recovers from worker crashes.
    
    Finds scans stuck in RUNNING for > 45 minutes and refunds users.
    
    Why 45 minutes?
    - Celery has 30-minute task timeout
    - Add 15-minute buffer for grace period
    - If still RUNNING after 45 mins, worker definitely crashed (SIGKILL/OOM)
    
    This prevents permanent credit loss when:
    - Workers get OOM killed
    - Docker containers are redeployed
    - Servers crash during scans
    - Network partitions occur
    """
    asyncio.run(_sweep_stale_scans_async())


async def _sweep_stale_scans_async():
    """Async implementation of stale scan sweeper."""
    from db import db
    from tasks import _refund_user
    
    cutoff_time = datetime.now() - timedelta(minutes=45)
    
    # Find stale scans
    # NOTE: This queries scans_db (mock) - Update to use Prisma when migrated
    # For now, we'll need to check Redis directly
    # TODO: Replace with Prisma query: 
    # stale_scans = await db.scan.find_many(
    #     where={"status": "RUNNING", "startedAt": {"lt": cutoff_time}},
    #     include={"target": {"include": {"user": True}}}
    # )
    
    # Temporary implementation using mock data
    from main import scans_db  # Import mock database
    
    stale_scans = []
    for scan_id, scan_data in scans_db.items():
        if scan_data.get("status") == "RUNNING":
            created_at = scan_data.get("created_at")
            if created_at and (datetime.now() - created_at).total_seconds() > 2700:  # 45 minutes
                stale_scans.append({
                    "id": scan_id,
                    "user_id": scan_data.get("user_id"),
                    "target": scan_data.get("target", {})
                })
    
    for scan in stale_scans:
        # Calculate cost
        cost = 0 if scan["target"].get("dry_run") else 10
        
        # Mark as failed in mock DB
        scans_db[scan["id"]]["status"] = "FAILED"
        
        # Refund user if it was a paid scan
        if cost > 0 and scan.get("user_id"):
            await _refund_user(
                user_id=scan["user_id"],
                amount=cost,
                scan_id=scan["id"],
                reason="STALE_JOB_TIMEOUT (Worker crashed/redeployed)"
            )
            
        print(f"🧹 Swept stale scan {scan['id'][:8]} and refunded {cost} credits to user {scan.get('user_id', 'unknown')[:8]}")
    
    if stale_scans:
        print(f"✅ Sweeper recovered {len(stale_scans)} stale jobs")
    
    return {"swept_count": len(stale_scans)}
