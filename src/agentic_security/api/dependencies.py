"""FastAPI dependency injection utilities."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from .database import Database
from .services.target_service import TargetService
from .services.test_service import TestService

# Global database instance (set during app startup)
_db_instance: Database = None


def set_database(db: Database) -> None:
    """Set the global database instance.

    Args:
        db: Database instance to use.
    """
    global _db_instance
    _db_instance = db


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session.

    Yields:
        AsyncSession for database operations.

    Raises:
        RuntimeError: If database not initialized.
    """
    if not _db_instance:
        raise RuntimeError("Database not initialized")

    async for session in _db_instance.get_session():
        yield session


async def get_target_service(
    db: AsyncSession = None,
) -> TargetService:
    """Get target service instance.

    Args:
        db: Optional database session.

    Returns:
        TargetService instance.
    """
    return TargetService(db)


async def get_test_service(
    db: AsyncSession = None,
) -> TestService:
    """Get test service instance.

    Args:
        db: Optional database session.

    Returns:
        TestService instance.
    """
    return TestService(db)
