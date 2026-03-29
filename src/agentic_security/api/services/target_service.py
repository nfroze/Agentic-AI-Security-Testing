"""Target management service."""

import logging
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ...core.config import TargetConfig
from ...core.enums import TargetProvider
from ...core.exceptions import TargetConnectionError
from ...targets.base import BaseTarget
from ...targets.openai_target import OpenAITarget
from ..schemas import TargetCreate, TargetResponse, TargetUpdate
from ...results.models import Target

logger = logging.getLogger(__name__)


class TargetService:
    """Service for managing target systems."""

    def __init__(self, db: Optional[AsyncSession] = None):
        """Initialize target service.

        Args:
            db: Optional database session.
        """
        self.db = db
        self._target_cache: dict[str, BaseTarget] = {}

    async def create_target(self, request: TargetCreate) -> TargetResponse:
        """Create and register a new target.

        Args:
            request: Target creation request.

        Returns:
            TargetResponse with created target info.

        Raises:
            TargetConnectionError: If unable to connect to target.
        """
        from datetime import datetime

        target_id = f"target_{uuid4().hex[:8]}"

        # Validate connectivity
        target_instance = self._create_target_instance(request)
        if not await target_instance.health_check():
            raise TargetConnectionError(
                f"Unable to connect to target at {request.endpoint_url}"
            )

        # Store target instance in cache
        self._target_cache[target_id] = target_instance

        created_at = datetime.utcnow()

        # Persist to database if available
        if self.db:
            db_target = Target(
                id=target_id,
                provider=request.provider,
                model_name=request.model_name,
                endpoint_url=request.endpoint_url,
                metadata={
                    "name": request.name,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                    "custom_headers": request.custom_headers,
                    "request_template": request.request_template,
                    "response_path": request.response_path,
                },
            )
            self.db.add(db_target)
            await self.db.commit()
            created_at = db_target.created_at

        logger.info(f"Created target: {target_id}")

        return TargetResponse(
            id=target_id,
            name=request.name,
            endpoint_url=request.endpoint_url,
            model_name=request.model_name,
            provider=request.provider,
            created_at=created_at,
        )

    async def get_target(self, target_id: str) -> Optional[TargetResponse]:
        """Get target by ID.

        Args:
            target_id: Target identifier.

        Returns:
            TargetResponse or None if not found.
        """
        if self.db:
            stmt = select(Target).where(Target.id == target_id)
            result = await self.db.execute(stmt)
            db_target = result.scalar_one_or_none()

            if not db_target:
                return None

            metadata = db_target.metadata or {}
            return TargetResponse(
                id=db_target.id,
                name=metadata.get("name", "Unknown"),
                endpoint_url=db_target.endpoint_url,
                model_name=db_target.model_name,
                provider=db_target.provider,
                created_at=db_target.created_at,
            )

        return None

    async def list_targets(self) -> list[TargetResponse]:
        """List all registered targets.

        Returns:
            List of TargetResponse objects.
        """
        targets = []

        if self.db:
            stmt = select(Target)
            result = await self.db.execute(stmt)
            db_targets = result.scalars().all()

            for db_target in db_targets:
                metadata = db_target.metadata or {}
                targets.append(
                    TargetResponse(
                        id=db_target.id,
                        name=metadata.get("name", "Unknown"),
                        endpoint_url=db_target.endpoint_url,
                        model_name=db_target.model_name,
                        provider=db_target.provider,
                        created_at=db_target.created_at,
                    )
                )

        return targets

    async def update_target(
        self, target_id: str, request: TargetUpdate
    ) -> Optional[TargetResponse]:
        """Update a target's configuration.

        Args:
            target_id: Target identifier.
            request: Update request.

        Returns:
            Updated TargetResponse or None if not found.
        """
        if not self.db:
            return None

        stmt = select(Target).where(Target.id == target_id)
        result = await self.db.execute(stmt)
        db_target = result.scalar_one_or_none()

        if not db_target:
            return None

        # Update metadata
        metadata = db_target.metadata or {}
        if request.name:
            metadata["name"] = request.name
        if request.max_tokens:
            metadata["max_tokens"] = request.max_tokens
        if request.temperature is not None:
            metadata["temperature"] = request.temperature
        if request.custom_headers:
            metadata["custom_headers"] = request.custom_headers
        if request.request_template:
            metadata["request_template"] = request.request_template
        if request.response_path:
            metadata["response_path"] = request.response_path

        if request.endpoint_url:
            db_target.endpoint_url = request.endpoint_url
        if request.model_name:
            db_target.model_name = request.model_name
        if request.provider:
            db_target.provider = request.provider

        db_target.metadata = metadata
        await self.db.commit()

        # Invalidate cache
        if target_id in self._target_cache:
            del self._target_cache[target_id]

        logger.info(f"Updated target: {target_id}")

        return TargetResponse(
            id=db_target.id,
            name=metadata.get("name", "Unknown"),
            endpoint_url=db_target.endpoint_url,
            model_name=db_target.model_name,
            provider=db_target.provider,
            created_at=db_target.created_at,
        )

    async def delete_target(self, target_id: str) -> bool:
        """Delete a target.

        Args:
            target_id: Target identifier.

        Returns:
            True if deleted, False if not found.
        """
        if not self.db:
            return False

        stmt = select(Target).where(Target.id == target_id)
        result = await self.db.execute(stmt)
        db_target = result.scalar_one_or_none()

        if not db_target:
            return False

        await self.db.delete(db_target)
        await self.db.commit()

        # Clear cache
        if target_id in self._target_cache:
            del self._target_cache[target_id]

        logger.info(f"Deleted target: {target_id}")
        return True

    async def health_check(self, target_id: str) -> bool:
        """Check if a target is healthy.

        Args:
            target_id: Target identifier.

        Returns:
            True if healthy, False otherwise.
        """
        target = await self._get_target_instance(target_id)
        if not target:
            return False

        return await target.health_check()

    async def _get_target_instance(self, target_id: str) -> Optional[BaseTarget]:
        """Get or load a target instance.

        Args:
            target_id: Target identifier.

        Returns:
            BaseTarget instance or None.
        """
        if target_id in self._target_cache:
            return self._target_cache[target_id]

        if not self.db:
            return None

        stmt = select(Target).where(Target.id == target_id)
        result = await self.db.execute(stmt)
        db_target = result.scalar_one_or_none()

        if not db_target:
            return None

        # Reconstruct TargetCreate from database
        metadata = db_target.metadata or {}
        request = TargetCreate(
            name=metadata.get("name", db_target.model_name),
            endpoint_url=db_target.endpoint_url,
            api_key="***",  # Can't recover, would need to be replaced during update
            model_name=db_target.model_name,
            provider=db_target.provider,
            max_tokens=metadata.get("max_tokens", 2000),
            temperature=metadata.get("temperature", 0.7),
            custom_headers=metadata.get("custom_headers"),
            request_template=metadata.get("request_template"),
            response_path=metadata.get("response_path"),
        )

        target = self._create_target_instance(request)
        self._target_cache[target_id] = target
        return target

    @staticmethod
    def _create_target_instance(request: TargetCreate) -> BaseTarget:
        """Create a target instance based on provider.

        Args:
            request: Target creation request.

        Returns:
            BaseTarget subclass instance.

        Raises:
            ValueError: If provider is unsupported.
        """
        config = TargetConfig(
            endpoint_url=request.endpoint_url,
            api_key=request.api_key,
            model_name=request.model_name,
            provider=TargetProvider(request.provider),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )

        if request.provider.lower() == "openai":
            return OpenAITarget(config)
        # TODO: Add AnthropicTarget, CustomTarget
        else:
            raise ValueError(f"Unsupported provider: {request.provider}")
