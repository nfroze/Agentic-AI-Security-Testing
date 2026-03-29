"""OpenAI-compatible target implementation."""

import asyncio
import json
import logging
from typing import Optional

import httpx

from ..core.base import Conversation
from ..core.config import TargetConfig
from ..core.exceptions import (
    RateLimitError,
    TargetConnectionError,
    TargetResponseError,
)
from .base import BaseTarget

logger = logging.getLogger(__name__)


class OpenAITarget(BaseTarget):
    """Target for OpenAI API or compatible endpoints (Azure, local models, etc.)."""

    def __init__(self, config: TargetConfig):
        """Initialize OpenAI target.

        Args:
            config: Target configuration. Must have endpoint_url, api_key, model_name.
        """
        super().__init__(config)
        self._client = httpx.AsyncClient(
            base_url=config.endpoint_url,
            timeout=config.timeout_seconds,
            headers={"Authorization": f"Bearer {config.api_key.get_secret_value()}"},
        )
        self._rate_limiter = asyncio.Semaphore(config.rate_limit_rpm // 60)

    async def send_prompt(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """Send a single prompt to the OpenAI-compatible endpoint.

        Args:
            prompt: The user prompt.
            system_prompt: Optional system prompt.

        Returns:
            The model's response.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response from target.
            RateLimitError: Rate limit exceeded.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        return await self._send_request(messages)

    async def send_conversation(self, conversation: Conversation) -> str:
        """Send a multi-turn conversation to the endpoint.

        Args:
            conversation: Conversation with message history.

        Returns:
            The model's response.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response from target.
        """
        messages = [
            {"role": m.role, "content": m.content} for m in conversation.messages
        ]
        return await self._send_request(messages)

    async def _send_request(self, messages: list[dict]) -> str:
        """Internal method to send a request to the OpenAI endpoint.

        Args:
            messages: Message list in OpenAI format.

        Returns:
            The response text.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response.
            RateLimitError: Rate limit hit.
        """
        async with self._rate_limiter:
            payload = {
                "model": self.config.model_name,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            }

            for attempt in range(3):
                try:
                    response = await self._client.post(
                        "/v1/chat/completions",
                        json=payload,
                    )

                    if response.status_code == 429:
                        raise RateLimitError("Rate limit exceeded on target")

                    response.raise_for_status()
                    data = response.json()

                    if "choices" not in data or not data["choices"]:
                        raise TargetResponseError(
                            f"Unexpected response format: {data}"
                        )

                    return data["choices"][0]["message"]["content"]

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        raise RateLimitError("Rate limit exceeded on target") from e
                    if attempt == 2:
                        raise TargetResponseError(
                            f"Target returned {e.response.status_code}: {e.response.text}"
                        ) from e
                    await asyncio.sleep(2 ** attempt)

                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    if attempt == 2:
                        raise TargetConnectionError(
                            f"Failed to connect to target after 3 attempts: {e}"
                        ) from e
                    await asyncio.sleep(2 ** attempt)

                except json.JSONDecodeError as e:
                    raise TargetResponseError(
                        f"Invalid JSON in target response: {e}"
                    ) from e

    async def health_check(self) -> bool:
        """Verify target is reachable.

        Returns:
            True if target responds, False otherwise.
        """
        try:
            response = await self._client.post(
                "/v1/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 10,
                },
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False

    async def close(self) -> None:
        """Close the HTTP client connection."""
        await self._client.aclose()
