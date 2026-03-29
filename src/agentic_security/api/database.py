"""Database connection and session management."""

import logging
import os
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from ..results.models import Base

logger = logging.getLogger(__name__)


class Database:
    """Manages database connections and session lifecycle."""

    def __init__(self, database_url: Optional[str] = None):
        """Initialize database manager.

        Args:
            database_url: SQLAlchemy async database URL.
                If None, uses DATABASE_URL env var or defaults to SQLite.
        """
        if database_url is None:
            database_url = os.getenv(
                "DATABASE_URL", "sqlite+aiosqlite:///agentic_security.db"
            )

        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None

    async def initialize(self) -> None:
        """Initialize the database engine and create tables."""
        logger.info(f"Initializing database: {self.database_url}")

        # Create async engine
        self.engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database initialized successfully")

    async def close(self) -> None:
        """Close database engine and cleanup."""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connection closed")

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session.

        Yields:
            AsyncSession for database operations.

        Raises:
            RuntimeError: If database not initialized.
        """
        if not self.SessionLocal:
            raise RuntimeError(
                "Database not initialized. Call initialize() first."
            )

        session = self.SessionLocal()
        try:
            yield session
        finally:
            await session.close()
