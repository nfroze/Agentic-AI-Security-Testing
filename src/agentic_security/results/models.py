"""SQLAlchemy models for persisting test results to a database."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from agentic_security.core.base import AttackResult, TestSuiteResult

Base = declarative_base()


class TestRun(Base):
    """Represents a single test run/suite execution."""

    __tablename__ = "test_runs"

    id = Column(String(64), primary_key=True)
    target_name = Column(String(255), index=True)
    category = Column(Text, index=True)
    status = Column(String(32), default="PENDING")
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    summary = Column(JSON)
    metadata_dict = Column(JSON)


class TestResult(Base):
    """Represents a single attack result within a test run."""

    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_run_id = Column(String(64), index=True)
    payload_id = Column(String(255), index=True)
    payload_category = Column(String(64), index=True)
    technique = Column(String(255))
    target_response = Column(Text)
    success = Column(Integer)  # Boolean as integer
    confidence = Column(Float)
    severity = Column(String(32))
    execution_time_ms = Column(Integer)
    scorer_details = Column(JSON)
    conversation = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class Target(Base):
    """Represents a tested target system."""

    __tablename__ = "targets"

    id = Column(String(255), primary_key=True)
    provider = Column(String(32), index=True)
    model_name = Column(String(255), index=True)
    endpoint_url = Column(String(512))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_tested_at = Column(DateTime, nullable=True)
    metadata_dict = Column(JSON)


class AttackPayloadRecord(Base):
    """Cached attack payload records."""

    __tablename__ = "attack_payloads"

    id = Column(String(255), primary_key=True)
    category = Column(String(64), index=True)
    technique = Column(String(255), index=True)
    content = Column(Text)
    expected_behavior = Column(Text)
    tags = Column(JSON)  # List of tags
    metadata_dict = Column(JSON)


class ResultsDatabase:
    """Manager for results database connections and operations."""

    def __init__(self, database_url: str):
        """Initialize database manager.

        Args:
            database_url: SQLAlchemy async database URL
                         (e.g., 'postgresql+asyncpg://user:pass@localhost/dbname').
        """
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None

    async def initialize(self) -> None:
        """Initialize the database engine and create tables."""
        self.engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_pre_ping=True,
        )

        self.SessionLocal = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        """Close database connections."""
        if self.engine:
            await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        """Get a new database session.

        Returns:
            AsyncSession instance.
        """
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.SessionLocal()


class ResultsStore(ABC):
    """Abstract interface for storing and querying test results."""

    @abstractmethod
    async def save_test_run(self, test_run: TestSuiteResult) -> str:
        """Save a test run to the store.

        Args:
            test_run: TestSuiteResult instance to save.

        Returns:
            Test run ID.
        """
        pass

    @abstractmethod
    async def save_result(
        self, test_run_id: str, result: AttackResult
    ) -> str:
        """Save an individual attack result to a test run.

        Args:
            test_run_id: ID of the test run.
            result: AttackResult instance to save.

        Returns:
            Result ID.
        """
        pass

    @abstractmethod
    async def get_test_run(self, test_run_id: str) -> Optional[TestSuiteResult]:
        """Retrieve a test run by ID.

        Args:
            test_run_id: ID of the test run to retrieve.

        Returns:
            TestSuiteResult instance or None if not found.
        """
        pass

    @abstractmethod
    async def get_results(
        self,
        test_run_id: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[AttackResult]:
        """Retrieve results for a test run with optional filtering.

        Args:
            test_run_id: ID of the test run.
            filters: Optional filter dict with keys like 'category', 'severity', 'success'.

        Returns:
            List of AttackResult instances matching filters.
        """
        pass

    @abstractmethod
    async def get_summary(self, test_run_id: str) -> dict[str, Any]:
        """Get summary statistics for a test run.

        Args:
            test_run_id: ID of the test run.

        Returns:
            Dictionary with summary stats (total, passed, failed, pass_rate, etc.).
        """
        pass

    @abstractmethod
    async def list_test_runs(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TestSuiteResult]:
        """List test runs with pagination.

        Args:
            limit: Maximum number of results to return.
            offset: Number of results to skip.

        Returns:
            List of TestSuiteResult instances.
        """
        pass
