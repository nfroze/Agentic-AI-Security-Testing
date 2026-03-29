"""Test run management endpoints."""

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..dependencies import get_db
from ..schemas import (
    PaginatedResponse,
    TestResultDetail,
    TestResultResponse,
    TestRunCreate,
    TestRunResponse,
)
from ..services.test_service import TestService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tests", tags=["tests"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_test(
    request: TestRunCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Create and start a new test run.

    Args:
        request: Test run creation request.
        db: Database session.

    Returns:
        Test run ID.

    Raises:
        HTTPException: If test creation fails.
    """
    try:
        service = TestService(db)
        test_id = await service.create_and_run_test(request)
        return {"test_id": test_id}
    except ValueError as e:
        logger.error(f"Invalid test request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error creating test: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get("")
async def list_tests(
    status_filter: Optional[str] = None,
    target_id: Optional[str] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
) -> list[TestRunResponse]:
    """List test runs with optional filtering.

    Args:
        status_filter: Filter by status (PENDING, RUNNING, COMPLETED, FAILED, CANCELLED).
        target_id: Filter by target ID.
        db: Database session.

    Returns:
        List of test run responses.
    """
    from sqlalchemy.future import select

    from ...results.models import TestRun
    from .target_service import TargetService

    if not db:
        return []

    # Build query
    query = select(TestRun)

    if status_filter:
        query = query.where(TestRun.status == status_filter)

    if target_id:
        # Filter by target_id in metadata
        # For now, we'll just query all and filter in Python
        pass

    result = await db.execute(query)
    db_test_runs = result.scalars().all()

    # Convert to response schemas
    responses = []
    target_service = TargetService(db)

    for db_test_run in db_test_runs:
        metadata = db_test_run.metadata or {}
        test_target_id = metadata.get("target_id")

        target = None
        if test_target_id:
            target = await target_service.get_target(test_target_id)

        categories = db_test_run.category.split(",") if db_test_run.category else []

        summary = None
        if db_test_run.summary:
            from ..schemas import SummaryStats
            summary_data = db_test_run.summary
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

        responses.append(
            TestRunResponse(
                id=db_test_run.id,
                target=target,
                status=db_test_run.status,
                attack_categories=categories,
                started_at=db_test_run.started_at,
                completed_at=db_test_run.completed_at,
                summary=summary,
            )
        )

    return responses


@router.get("/{test_id}")
async def get_test(
    test_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TestRunResponse:
    """Get test run status and summary.

    Args:
        test_id: Test run ID.
        db: Database session.

    Returns:
        Test run response.

    Raises:
        HTTPException: If test not found.
    """
    service = TestService(db)
    test_run = await service.get_test_run(test_id)

    if not test_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {test_id} not found",
        )

    return test_run


@router.get("/{test_id}/results")
async def get_results(
    test_id: str,
    page: int = 1,
    page_size: int = 20,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
) -> PaginatedResponse[TestResultResponse]:
    """Get paginated test results.

    Args:
        test_id: Test run ID.
        page: Page number (1-indexed).
        page_size: Results per page.
        db: Database session.

    Returns:
        Paginated results.

    Raises:
        HTTPException: If test not found.
    """
    service = TestService(db)

    # Verify test exists
    test_run = await service.get_test_run(test_id)
    if not test_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {test_id} not found",
        )

    # Get results
    results, total = await service.get_results(test_id, page, page_size)

    # Convert to response schemas (truncated)
    response_results = []
    for result in results:
        # Get category info
        from ...core.enums import OWASPAgenticCategory, OWASPLLMCategory

        _category_name = "Unknown"
        category_description = "Unknown"

        for cat in OWASPLLMCategory:
            if cat.code == result.payload_category:
                _category_name = cat.name_str
                category_description = cat.description
                break

        for cat in OWASPAgenticCategory:
            if cat.code == result.payload_category:
                _category_name = cat.name_str
                category_description = cat.description
                break

        response_results.append(
            TestResultResponse(
                id=result.id,
                test_run_id=result.test_run_id,
                attack_name=result.technique,
                owasp_category=result.payload_category,
                owasp_category_description=category_description,
                severity=result.severity,
                payload_content=result.payload_id[:200],
                target_response=result.target_response[:500]
                if result.target_response
                else "",
                success=bool(result.success),
                confidence=result.confidence,
                execution_time_ms=result.execution_time_ms,
                created_at=result.created_at,
            )
        )

    pages = (total + page_size - 1) // page_size

    return PaginatedResponse(
        items=response_results,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{test_id}/results/{result_id}")
async def get_result_detail(
    test_id: str,
    result_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TestResultDetail:
    """Get a single result with full details.

    Args:
        test_id: Test run ID.
        result_id: Result ID.
        db: Database session.

    Returns:
        Full result detail.

    Raises:
        HTTPException: If result not found.
    """
    service = TestService(db)
    result = await service.get_result_detail(test_id, result_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Result {result_id} not found",
        )

    # Get category info
    from ...core.enums import OWASPAgenticCategory, OWASPLLMCategory

    _category_name = "Unknown"
    category_description = "Unknown"

    for cat in OWASPLLMCategory:
        if cat.code == result.payload_category:
            _category_name = cat.name_str
            category_description = cat.description
            break

    for cat in OWASPAgenticCategory:
        if cat.code == result.payload_category:
            _category_name = cat.name_str
            category_description = cat.description
            break

    return TestResultDetail(
        id=result.id,
        test_run_id=result.test_run_id,
        attack_name=result.technique,
        owasp_category=result.payload_category,
        owasp_category_description=category_description,
        severity=result.severity,
        payload_content=result.payload_id,
        target_response=result.target_response or "",
        success=bool(result.success),
        confidence=result.confidence,
        execution_time_ms=result.execution_time_ms,
        scorer_details=result.scorer_details or {},
        created_at=result.created_at,
    )


@router.post("/{test_id}/cancel")
async def cancel_test(
    test_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Cancel a running test.

    Args:
        test_id: Test run ID.
        db: Database session.

    Returns:
        Status message.

    Raises:
        HTTPException: If test not found or cannot be cancelled.
    """
    service = TestService(db)

    # Verify test exists
    test_run = await service.get_test_run(test_id)
    if not test_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {test_id} not found",
        )

    # Attempt cancellation
    cancelled = await service.cancel_test_run(test_id)

    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Test {test_id} is not running and cannot be cancelled",
        )

    return {"message": f"Test {test_id} cancelled successfully"}
