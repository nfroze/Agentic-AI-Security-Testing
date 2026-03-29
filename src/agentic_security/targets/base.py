"""Abstract base class for target LLM/agent systems."""

from abc import ABC, abstractmethod
from typing import Optional

from ..core.base import Conversation, Message
from ..core.config import TargetConfig


class BaseTarget(ABC):
    """Base interface for all target systems.

    Targets abstract away the interaction mechanism with LLM/agent endpoints.
    They handle authentication, retries, rate limiting, and response normalization.
    """

    def __init__(self, config: TargetConfig):
        """Initialize target with configuration.

        Args:
            config: Target configuration including endpoint, API key, model name.
        """
        self.config = config
        self._conversation_history: list[Message] = []

    @abstractmethod
    async def send_prompt(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """Send a single prompt and return the response text.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt to override model behavior.

        Returns:
            The model's response text.

        Raises:
            TargetConnectionError: If unable to connect to target.
            TargetResponseError: If target returns an error.
        """
        ...

    @abstractmethod
    async def send_conversation(self, conversation: Conversation) -> str:
        """Send a full conversation (for multi-turn attacks) and return response.

        Args:
            conversation: A conversation with multiple turns.

        Returns:
            The model's final response.

        Raises:
            TargetConnectionError: If unable to connect to target.
            TargetResponseError: If target returns an error.
        """
        ...

    async def reset_conversation(self) -> None:
        """Reset conversation history for fresh attack chain."""
        self._conversation_history = []

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify target is reachable and responding.

        Returns:
            True if target is healthy, False otherwise.
        """
        ...

    @property
    def provider_name(self) -> str:
        """Return the target provider name."""
        return self.config.provider.code

    @property
    def model_name(self) -> str:
        """Return the target model name."""
        return self.config.model_name

    @property
    def conversation_history(self) -> list[Message]:
        """Return the current conversation history."""
        return self._conversation_history.copy()
