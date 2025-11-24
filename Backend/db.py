"""
Database Connection Manager using Prisma ORM

This module provides a singleton Prisma client for managing database connections
across the application. It ensures proper connection pooling and lifecycle management.
"""

from prisma import Prisma

# Global Prisma Client Singleton
db = Prisma()


async def connect_db():
    """
    Connects to the database if not already connected.
    Should be called during application startup.
    """
    if not db.is_connected():
        await db.connect()
        print("✅ Database connected successfully")


async def disconnect_db():
    """
    Disconnects from the database if connected.
    Should be called during application shutdown.
    """
    if db.is_connected():
        await db.disconnect()
        print("📤 Database disconnected")
