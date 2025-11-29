"""
Database Connection Manager for Vaptiq.ai

Security Features:
- Singleton Prisma client pattern
- SSL/TLS enforcement in production (MEDIUM-012)
- Connection validation
"""
from prisma import Prisma
import os
import logging

logger = logging.getLogger(__name__)

# Global database client instance (singleton pattern)
db = Prisma()

async def connect_db():
    """
    Connect to the database with security validations.
    
    Security:
    - Validates SSL mode in production
    - Prevents insecure connections
    """
    if not db.is_connected():
        # ============================================================================
        # SECURITY: SSL Validation (MEDIUM-012)
        # ============================================================================
        database_url = os.getenv("DATABASE_URL", "")
        environment = os.getenv("ENVIRONMENT", "development")
        
        if environment == "production":
            # Enforce SSL in production
            if "sslmode=require" not in database_url and "sslmode=verify" not in database_url:
                raise ValueError(
                    "❌ SECURITY ERROR: Database SSL required in production!\\n"
                    "DATABASE_URL must include 'sslmode=require' or 'sslmode=verify-full'\\n"
                    "Example: postgresql://user:pass@host:5432/db?sslmode=require"
                )
            logger.info("✅ Database SSL validation passed (production mode)")
        
        await db.connect()
        logger.info("✅ Database connected successfully")


async def disconnect_db():
    """
    Disconnect from the database if connected.
    Should be called during application shutdown.
    """
    if db.is_connected():
        await db.disconnect()
        logger.info("📤 Database disconnected")
