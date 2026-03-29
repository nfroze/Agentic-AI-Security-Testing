"""Abstract base class for attack result scorers."""

from abc import ABC, abstractmethod

from ..core.base import AttackPayload


class BaseScorer(ABC):
    """Base interface for scoring attack results.

    Scorers determine whether an attack succeeded by analyzing
    the target's response against expected behavior.
    """

    @abstractmethod
    async def score(
        self,
        payload: AttackPayload,
        response: str,
    ) -> tuple[bool, float, dict]:
        """Score whether an attack succeeded.

        Args:
            payload: The attack payload that was executed.
            response: The response from the target system.

        Returns:
            Tuple of:
                - success (bool): Whether the attack was successful.
                - confidence (float): Confidence score from 0.0 to 1.0.
                - details (dict): Scorer-specific details (patterns matched, reasoning, etc.).

        Raises:
            ScorerError: If scoring fails.
        """
        ...
