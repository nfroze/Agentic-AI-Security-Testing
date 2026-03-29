"""In-memory results store implementation for local development."""

import asyncio
import uuid
from datetime import datetime
from typing import Any, Optional

from agentic_security.core.base import AttackResult, TestSuiteResult
from agentic_security.core.enums import Severity

from .models import ResultsStore


class InMemoryResultsStore(ResultsStore):
    """Thread-safe in-memory results store.

    Stores test runs and results in dictionaries with asyncio.Lock for thread safety.
    Supports filtering by category, severity, and success status.
    Calculates summary statistics on the fly.
    """

    def __init__(self):
        """Initialize the in-memory store."""
        self._test_runs: dict[str, TestSuiteResult] = {}
        self._results: dict[str, list[AttackResult]] = {}
        self._lock = asyncio.Lock()

    async def save_test_run(self, test_run: TestSuiteResult) -> str:
        """Save a test run to the store.

        Args:
            test_run: TestSuiteResult instance to save.

        Returns:
            Test run ID.
        """
        async with self._lock:
            test_run_id = test_run.test_id or str(uuid.uuid4())
            self._test_runs[test_run_id] = test_run
            self._results[test_run_id] = []
            return test_run_id

    async def save_result(
        self,
        test_run_id: str,
        result: AttackResult,
    ) -> str:
        """Save an individual attack result to a test run.

        Args:
            test_run_id: ID of the test run.
            result: AttackResult instance to save.

        Returns:
            Result ID (UUID).

        Raises:
            KeyError: If test_run_id not found.
        """
        async with self._lock:
            if test_run_id not in self._results:
                raise KeyError(f"Test run {test_run_id} not found")

            self._results[test_run_id].append(result)
            return str(uuid.uuid4())

    async def get_test_run(self, test_run_id: str) -> Optional[TestSuiteResult]:
        """Retrieve a test run by ID.

        Args:
            test_run_id: ID of the test run to retrieve.

        Returns:
            TestSuiteResult instance or None if not found.
        """
        async with self._lock:
            return self._test_runs.get(test_run_id)

    async def get_results(
        self,
        test_run_id: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[AttackResult]:
        """Retrieve results for a test run with optional filtering.

        Supported filters:
        - 'category': str or list of OWASP category codes (e.g., 'LLM01', 'ASI01')
        - 'severity': Severity enum or str (e.g., 'CRITICAL', 'HIGH')
        - 'success': bool (True for successful attacks, False for failures)
        - 'technique': str (exact match on technique name)

        Args:
            test_run_id: ID of the test run.
            filters: Optional filter dict with category, severity, success, technique keys.

        Returns:
            List of AttackResult instances matching filters.
        """
        async with self._lock:
            if test_run_id not in self._results:
                return []

            results = self._results[test_run_id]

            if not filters:
                return results

            filtered = results
            if "category" in filters:
                cat_filter = filters["category"]
                if isinstance(cat_filter, str):
                    cat_filter = [cat_filter]
                filtered = [
                    r
                    for r in filtered
                    if (
                        hasattr(r.payload.category, "code")
                        and r.payload.category.code in cat_filter
                    )
                    or (
                        isinstance(r.payload.category, str)
                        and r.payload.category in cat_filter
                    )
                ]

            if "severity" in filters:
                sev_filter = filters["severity"]
                if isinstance(sev_filter, str):
                    try:
                        sev_filter = Severity[sev_filter]
                    except KeyError:
                        pass
                filtered = [r for r in filtered if r.severity == sev_filter]

            if "success" in filters:
                filtered = [r for r in filtered if r.success == filters["success"]]

            if "technique" in filters:
                filtered = [
                    r
                    for r in filtered
                    if r.payload.technique == filters["technique"]
                ]

            return filtered

    async def get_summary(self, test_run_id: str) -> dict[str, Any]:
        """Get summary statistics for a test run.

        Args:
            test_run_id: ID of the test run.

        Returns:
            Dictionary with summary stats (total, passed, failed, pass_rate,
            critical_count, high_count, avg_confidence, etc.).
        """
        async with self._lock:
            if test_run_id not in self._results:
                return {}

            results = self._results[test_run_id]
            total = len(results)

            if total == 0:
                return {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "pass_rate": 0.0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "avg_confidence": 0.0,
                }

            passed = sum(1 for r in results if not r.success)
            failed = sum(1 for r in results if r.success)

            severity_counts = {
                "critical_count": sum(
                    1
                    for r in results
                    if r.success and r.severity == Severity.CRITICAL
                ),
                "high_count": sum(
                    1 for r in results if r.success and r.severity == Severity.HIGH
                ),
                "medium_count": sum(
                    1
                    for r in results
                    if r.success and r.severity == Severity.MEDIUM
                ),
                "low_count": sum(
                    1 for r in results if r.success and r.severity == Severity.LOW
                ),
            }

            return {
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": (passed / total * 100) if total > 0 else 0.0,
                "avg_confidence": sum(r.confidence for r in results) / total,
                **severity_counts,
            }

    async def list_test_runs(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TestSuiteResult]:
        """List test runs with pagination, sorted by most recent first.

        Args:
            limit: Maximum number of results to return.
            offset: Number of results to skip.

        Returns:
            List of TestSuiteResult instances.
        """
        async with self._lock:
            test_runs = sorted(
                self._test_runs.values(),
                key=lambda x: x.started_at,
                reverse=True,
            )
            return test_runs[offset : offset + limit]
