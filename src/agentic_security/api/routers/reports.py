"""Report generation endpoints."""

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..dependencies import get_db
from ..schemas import ReportResponse
from ..services.report_service import ReportService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/{test_id}")
async def get_report(
    test_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ReportResponse:
    """Generate a full assessment report for a test run.

    Args:
        test_id: Test run ID.
        db: Database session.

    Returns:
        Full assessment report.

    Raises:
        HTTPException: If test not found.
    """
    service = ReportService(db)
    report = await service.generate_report(test_id)

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {test_id} not found",
        )

    return report


@router.get("/{test_id}/export")
async def export_report(
    test_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Export report as JSON.

    Args:
        test_id: Test run ID.
        db: Database session.

    Returns:
        Report as JSON-serializable dict.

    Raises:
        HTTPException: If test not found.
    """
    service = ReportService(db)
    report = await service.generate_report(test_id)

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {test_id} not found",
        )

    # Convert to dict for JSON export
    return json.loads(report.model_dump_json())
