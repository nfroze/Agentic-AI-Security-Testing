"""Anthropic Claude target implementation."""

import asyncio
import json
import logging
from typing import Optional

import httpx

from ..core.base import Conversation, Message
from ..core.config import TargetConfig
from ..core.exceptions import (
    RateLimitError,
    TargetConnectionError,
    TargetResponseError,
)
from .base import BaseTarget

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicTarget(BaseTarget):
    """Target for Anthropic Claude API."""

    def __init__(self, config: TargetConfig):
        """Initialize Anthropic target.

        Args:
            config: Target configuration. Must have endpoint_url, api_key, model_name.
        """
        super().__init__(config)
        self._client = httpx.AsyncClient(
            base_url=config.endpoint_url,
            timeout=config.timeout_seconds,
            headers={
                "x-api-key": config.api_key.get_secret_value(),
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
        )
        self._rate_limiter = asyncio.Semaphore(config.rate_limit_rpm // 60)

    async def send_prompt(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """Send a single prompt to the Anthropic API.

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
        payload = {
            "model": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        return await self._send_request(payload)

    async def send_conversation(self, conversation: Conversation) -> str:
        """Send a multi-turn conversation to the Anthropic API.

        Args:
            conversation: Conversation with message history.

        Returns:
            The model's response.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response from target.
        """
        # Anthropic expects messages without system role
        messages = []
        system_prompt = None

        for msg in conversation.messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                messages.append({"role": msg.role, "content": msg.content})

        payload = {
            "model": self.config.model_name,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
        }

        if system_prompt:
            payload["system"] = system_prompt

        return await self._send_request(payload)

    async def _send_request(self, payload: dict) -> str:
        """Internal method to send a request to Anthropic API.

        Args:
            payload: Request payload in Anthropic format.

        Returns:
            The response text.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response.
            RateLimitError: Rate limit hit.
        """
        async with self._rate_limiter:
            for attempt in range(3):
                try:
                    response = await self._client.post(
                        "/v1/messages",
                        json=payload,
                    )

                    if response.status_code == 429:
                        raise RateLimitError("Rate limit exceeded on target")

                    response.raise_for_status()
                    data = response.json()

                    if "content" not in data or not data["content"]:
                        raise TargetResponseError(
                            f"Unexpected response format: {data}"
                        )

                    # Find the first text block in content
                    for block in data["content"]:
                        if block.get("type") == "text":
                            return block["text"]

                    raise TargetResponseError(
                        "No text content in Anthropic response"
                    )

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
                "/v1/messages",
                json={
                    "model": self.config.model_name,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                },
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False

    async def close(self) -> None:
        """Close the HTTP client connection."""
        await self._client.aclose()
