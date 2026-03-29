"""Test execution and result management service."""

import asyncio
import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ...attacks.registry import AttackRegistry
from ...core.config import OrchestratorConfig
from ...core.enums import TestStatus
from ...orchestrator.single_turn import SingleTurnOrchestrator
from ...results.models import TestResult, TestRun
from ...scorers.base import BaseScorer
from ...scorers.canary_scorer import CanaryScorer
from ...scorers.composite import CompositeScorer
from ...scorers.llm_judge import LLMJudgeScorer
from ...scorers.pattern_scorer import PatternScorer
from ..schemas import TestRunCreate, TestRunResponse
from .target_service import TargetService

logger = logging.getLogger(__name__)


class TestService:
    """Service for managing test execution and results."""

    def __init__(self, db: Optional[AsyncSession] = None):
        """Initialize test service.

        Args:
            db: Optional database session.
        """
        self.db = db
        self._target_service = TargetService(db)
        self._running_tests: dict[str, asyncio.Task] = {}

    async def create_and_run_test(self, request: TestRunCreate) -> str:
        """Create a test run and start execution.

        Args:
            request: Test run creation request.

        Returns:
            Test run ID.

        Raises:
            ValueError: If target not found.
        """
        test_id = f"test_{uuid4().hex[:8]}"

        # Verify target exists
        target = await self._target_service.get_target(request.target_id)
        if not target:
            raise ValueError(f"Target {request.target_id} not found")

        # Determine attack categories
        attack_categories = request.attack_categories or []

        # Create test run record
        if self.db:
            db_test_run = TestRun(
                id=test_id,
                target_name=target.model_name,
                category=",".join(attack_categories) if attack_categories else "ALL",
                status=TestStatus.PENDING.code,
                metadata={
                    "target_id": request.target_id,
                    "test_mode": request.test_mode,
                    "scorer_type": request.scorer_type,
                    "max_concurrent": request.max_concurrent,
                },
            )
            self.db.add(db_test_run)
            await self.db.commit()

        # Start test execution as background task
        task = asyncio.create_task(
            self._execute_test(
                test_id=test_id,
                target_id=request.target_id,
                attack_categories=attack_categories,
                test_mode=request.test_mode,
                max_concurrent=request.max_concurrent,
                scorer_type=request.scorer_type,
                canary_strings=request.canary_strings,
            )
        )
        self._running_tests[test_id] = task

        logger.info(f"Created and started test run: {test_id}")
        return test_id

    async def get_test_run(self, test_id: str) -> Optional[TestRunResponse]:
        """Get test run details and status.

        Args:
            test_id: Test run ID.

        Returns:
            TestRunResponse or None if not found.
        """
        if not self.db:
            return None

        stmt = select(TestRun).where(TestRun.id == test_id)
        result = await self.db.execute(stmt)
        db_test_run = result.scalar_one_or_none()

        if not db_test_run:
            return None

        # Get target info
        target_id = db_test_run.metadata.get("target_id") if db_test_run.metadata else None
        target = None
        if target_id:
            target = await self._target_service.get_target(target_id)

        # Build summary stats
        summary = None
        if db_test_run.summary:
            summary_data = db_test_run.summary
            from ..schemas import SummaryStats
            summary = SummaryStats(
                pass_count=summary_data.get("passed", 0),
                fail_count=summary_data.get("failed", 0),
                total=summary_data.get("total", 0),
                pass_rate=summary_data.get("pass_rate", 0.0),
                critical_count=summary_data.get("critical_count", 0),
                high_count=summary_data.get("high_count", 0),
                medium_count=summary_data.get("medium_count", 0),
                low_count=summary_data.get("low_count", 0),
            )

        categories = db_test_run.category.split(",") if db_test_run.category else []

        return TestRunResponse(
            id=test_id,
            target=target,
            status=db_test_run.status,
            attack_categories=categories,
            started_at=db_test_run.started_at,
            completed_at=db_test_run.completed_at,
            summary=summary,
        )

    async def get_results(
        self, test_id: str, page: int = 1, page_size: int = 20
    ) -> tuple[list, int]:
        """Get paginated test results.

        Args:
            test_id: Test run ID.
            page: Page number (1-indexed).
            page_size: Results per page.

        Returns:
            Tuple of (results, total_count).
        """
        if not self.db:
            return [], 0

        # Get total count
        count_stmt = select(TestResult).where(TestResult.test_run_id == test_id)
        count_result = await self.db.execute(count_stmt)
        total = len(count_result.scalars().all())

        # Get paginated results
        offset = (page - 1) * page_size
        stmt = (
            select(TestResult)
            .where(TestResult.test_run_id == test_id)
            .offset(offset)
            .limit(page_size)
        )
        result = await self.db.execute(stmt)
        results = result.scalars().all()

        return results, total

    async def get_result_detail(self, test_id: str, result_id: int):
        """Get a single result with full details.

        Args:
            test_id: Test run ID.
            result_id: Result ID.

        Returns:
            TestResult or None.
        """
        if not self.db:
            return None

        stmt = select(TestResult).where(
            (TestResult.test_run_id == test_id) & (TestResult.id == result_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def cancel_test_run(self, test_id: str) -> bool:
        """Cancel a running test.

        Args:
            test_id: Test run ID.

        Returns:
            True if cancelled, False if not running.
        """
        if test_id not in self._running_tests:
            return False

        task = self._running_tests[test_id]
        task.cancel()

        # Update status in database
        if self.db:
            stmt = select(TestRun).where(TestRun.id == test_id)
            result = await self.db.execute(stmt)
            db_test_run = result.scalar_one_or_none()
            if db_test_run:
                db_test_run.status = TestStatus.CANCELLED.code
                await self.db.commit()

        logger.info(f"Cancelled test run: {test_id}")
        return True

    async def _execute_test(
        self,
        test_id: str,
        target_id: str,
        attack_categories: list[str],
        test_mode: str,
        max_concurrent: int,
        scorer_type: str,
        canary_strings: Optional[list[str]] = None,
    ) -> None:
        """Execute a test run (background task).

        Args:
            test_id: Test run ID.
            target_id: Target ID.
            attack_categories: Categories to test (empty = all).
            test_mode: Test mode (single_turn, multi_turn).
            max_concurrent: Max concurrent attacks.
            scorer_type: Scorer type to use.
            canary_strings: Optional canary strings for canary scorer.
        """
        try:
            # Update status to RUNNING
            if self.db:
                stmt = select(TestRun).where(TestRun.id == test_id)
                result = await self.db.execute(stmt)
                db_test_run = result.scalar_one_or_none()
                if db_test_run:
                    db_test_run.status = TestStatus.RUNNING.code
                    db_test_run.started_at = datetime.utcnow()
                    await self.db.commit()

            # Get target instance
            target = await self._target_service._get_target_instance(target_id)
            if not target:
                raise ValueError(f"Target {target_id} not found")

            # Get attack modules
            if attack_categories:
                attacks = []
                for category in attack_categories:
                    attacks.extend(AttackRegistry.get_by_category(category))
            else:
                attacks = list(AttackRegistry.list_attacks().values())

            logger.info(f"Running {len(attacks)} attacks for test {test_id}")

            # Create scorer
            scorer = self._create_scorer(scorer_type, canary_strings)

            # Create orchestrator and run suite
            config = OrchestratorConfig(max_concurrent_tests=max_concurrent)
            orchestrator = SingleTurnOrchestrator(config)

            suite_result = await orchestrator.run_suite(attacks, target, scorer)

            # Store results
            if self.db:
                for attack_result in suite_result.results:
                    result_record = TestResult(
                        test_run_id=test_id,
                        payload_id=attack_result.payload.id,
                        payload_category=str(attack_result.payload.category),
                        technique=attack_result.payload.technique,
                        target_response=attack_result.target_response,
                        success=int(attack_result.success),
                        confidence=attack_result.confidence,
                        severity=attack_result.severity.code,
                        execution_time_ms=attack_result.execution_time_ms,
                        scorer_details=attack_result.scorer_details,
                    )
                    self.db.add(result_record)

                await self.db.commit()

                # Update test run with results
                stmt = select(TestRun).where(TestRun.id == test_id)
                result = await self.db.execute(stmt)
                db_test_run = result.scalar_one_or_none()
                if db_test_run:
                    db_test_run.status = TestStatus.COMPLETED.code
                    db_test_run.completed_at = datetime.utcnow()
                    db_test_run.summary = suite_result.summary
                    await self.db.commit()

            logger.info(
                f"Test run {test_id} completed: "
                f"{suite_result.summary['passed']} passed, "
                f"{suite_result.summary['failed']} failed"
            )

        except asyncio.CancelledError:
            logger.info(f"Test run {test_id} cancelled")
            if self.db:
                stmt = select(TestRun).where(TestRun.id == test_id)
                result = await self.db.execute(stmt)
                db_test_run = result.scalar_one_or_none()
                if db_test_run:
                    db_test_run.status = TestStatus.CANCELLED.code
                    await self.db.commit()

        except Exception as e:
            logger.error(f"Test run {test_id} failed: {e}", exc_info=True)
            if self.db:
                stmt = select(TestRun).where(TestRun.id == test_id)
                result = await self.db.execute(stmt)
                db_test_run = result.scalar_one_or_none()
                if db_test_run:
                    db_test_run.status = TestStatus.FAILED.code
                    db_test_run.completed_at = datetime.utcnow()
                    if db_test_run.metadata is None:
                        db_test_run.metadata = {}
                    db_test_run.metadata["error"] = str(e)
                    await self.db.commit()

    @staticmethod
    def _create_scorer(
        scorer_type: str, canary_strings: Optional[list[str]] = None
    ) -> BaseScorer:
        """Create a scorer instance.

        Args:
            scorer_type: Type of scorer.
            canary_strings: Optional canary strings.

        Returns:
            BaseScorer instance.

        Raises:
            ValueError: If scorer type unsupported.
        """
        if scorer_type == "pattern":
            return PatternScorer()
        elif scorer_type == "llm_judge":
            return LLMJudgeScorer()
        elif scorer_type == "canary":
            if not canary_strings:
                canary_strings = ["JAILBREAK_SUCCESSFUL", "CONFIRMED"]
            return CanaryScorer(canary_strings=canary_strings)
        elif scorer_type == "composite":
            return CompositeScorer()
        else:
            raise ValueError(f"Unsupported scorer type: {scorer_type}")
