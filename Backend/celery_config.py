"""
Hardened Celery Configuration for Production
"""
import os
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
