"""Target management endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.exceptions import TargetConnectionError
from ..dependencies import get_db
from ..schemas import TargetCreate, TargetResponse, TargetUpdate
from ..services.target_service import TargetService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_target(
    request: TargetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TargetResponse:
    """Register a new target system.

    Args:
        request: Target creation request.
        db: Database session.

    Returns:
        Created target response.

    Raises:
        HTTPException: If target creation fails.
    """
    try:
        service = TargetService(db)
        return await service.create_target(request)
    except TargetConnectionError as e:
        logger.error(f"Failed to connect to target: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to connect to target: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Error creating target: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("")
async def list_targets(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[TargetResponse]:
    """List all registered targets.

    Args:
        db: Database session.

    Returns:
        List of target responses.
    """
    service = TargetService(db)
    return await service.list_targets()


@router.get("/{target_id}")
async def get_target(
    target_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TargetResponse:
    """Get target details.

    Args:
        target_id: Target identifier.
        db: Database session.

    Returns:
        Target response.

    Raises:
        HTTPException: If target not found.
    """
    service = TargetService(db)
    target = await service.get_target(target_id)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found",
        )

    return target


@router.put("/{target_id}")
async def update_target(
    target_id: str,
    request: TargetUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TargetResponse:
    """Update target configuration.

    Args:
        target_id: Target identifier.
        request: Update request.
        db: Database session.

    Returns:
        Updated target response.

    Raises:
        HTTPException: If target not found.
    """
    service = TargetService(db)
    target = await service.update_target(target_id, request)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found",
        )

    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Delete a target.

    Args:
        target_id: Target identifier.
        db: Database session.

    Raises:
        HTTPException: If target not found.
    """
    service = TargetService(db)
    deleted = await service.delete_target(target_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found",
        )


@router.post("/{target_id}/health")
async def health_check(
    target_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, bool]:
    """Test target connectivity.

    Args:
        target_id: Target identifier.
        db: Database session.

    Returns:
        Health check result.

    Raises:
        HTTPException: If target not found.
    """
    service = TargetService(db)

    # Verify target exists
    target = await service.get_target(target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found",
        )

    # Run health check
    healthy = await service.health_check(target_id)

    return {"healthy": healthy}
