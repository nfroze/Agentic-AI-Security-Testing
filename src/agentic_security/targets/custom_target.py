"""Custom HTTP endpoint target implementation."""

import asyncio
import json
import logging
from typing import Optional

import httpx
import jinja2

from ..core.base import Conversation
from ..core.config import TargetConfig
from ..core.exceptions import (
    RateLimitError,
    TargetConnectionError,
    TargetResponseError,
)
from .base import BaseTarget

logger = logging.getLogger(__name__)


class CustomTarget(BaseTarget):
    """Target for arbitrary custom HTTP endpoints.

    Supports custom request/response formats via templates and JSON paths.
    """

    def __init__(
        self,
        config: TargetConfig,
        request_template: str,
        response_json_path: str,
        custom_headers: Optional[dict[str, str]] = None,
        auth_header: Optional[str] = None,
    ):
        """Initialize custom target.

        Args:
            config: Target configuration.
            request_template: Jinja2 template for request body with {prompt} placeholder.
            response_json_path: JSON path to extract response (e.g., 'data.response.text').
            custom_headers: Optional custom HTTP headers.
            auth_header: Optional custom authorization header.
        """
        super().__init__(config)
        self.request_template = jinja2.Template(request_template)
        self.response_json_path = response_json_path
        self.custom_headers = custom_headers or {}
        self.auth_header = auth_header

        headers = self.custom_headers.copy()
        if auth_header:
            headers["Authorization"] = auth_header

        self._client = httpx.AsyncClient(
            base_url=config.endpoint_url,
            timeout=config.timeout_seconds,
            headers=headers,
        )
        self._rate_limiter = asyncio.Semaphore(config.rate_limit_rpm // 60)

    async def send_prompt(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """Send a single prompt to the custom endpoint.

        Args:
            prompt: The user prompt.
            system_prompt: Optional system prompt (may be embedded in request_template).

        Returns:
            The model's response.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response from target.
        """
        body = self.request_template.render(
            prompt=prompt, system_prompt=system_prompt or ""
        )

        try:
            body_dict = json.loads(body)
        except json.JSONDecodeError:
            body_dict = {"prompt": body}

        return await self._send_request(body_dict)

    async def send_conversation(self, conversation: Conversation) -> str:
        """Send a multi-turn conversation to the custom endpoint.

        Args:
            conversation: Conversation with message history.

        Returns:
            The model's response.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response from target.
        """
        # Build a string representation of the conversation
        conv_text = "\n".join(
            f"{msg.role}: {msg.content}" for msg in conversation.messages
        )

        return await self.send_prompt(conv_text)

    async def _send_request(self, payload: dict) -> str:
        """Internal method to send a request.

        Args:
            payload: Request payload as dictionary.

        Returns:
            Extracted response text.

        Raises:
            TargetConnectionError: Connection failed.
            TargetResponseError: Invalid response.
        """
        async with self._rate_limiter:
            for attempt in range(3):
                try:
                    response = await self._client.post(
                        "",  # Use base_url
                        json=payload,
                    )

                    response.raise_for_status()
                    data = response.json()

                    # Extract response using JSON path
                    extracted = self._extract_by_path(data, self.response_json_path)
                    if extracted is None:
                        raise TargetResponseError(
                            f"Could not find response at path: {self.response_json_path}"
                        )

                    return str(extracted)

                except httpx.HTTPStatusError as e:
                    if response.status_code == 429:
                        raise RateLimitError("Rate limit exceeded on target") from e
                    if attempt == 2:
                        raise TargetResponseError(
                            f"Target returned {response.status_code}: {response.text}"
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

    @staticmethod
    def _extract_by_path(data: dict, path: str) -> Optional[str]:
        """Extract value from nested dict using dot-separated path.

        Args:
            data: Dictionary to extract from.
            path: Dot-separated path (e.g., 'data.response.text').

        Returns:
            Extracted value or None if path not found.
        """
        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    async def health_check(self) -> bool:
        """Verify target is reachable.

        Returns:
            True if target responds, False otherwise.
        """
        try:
            response = await self._client.post("", json={"test": True})
            return response.status_code in (200, 400, 422)  # Accept various responses
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False

    async def close(self) -> None:
        """Close the HTTP client connection."""
        await self._client.aclose()
