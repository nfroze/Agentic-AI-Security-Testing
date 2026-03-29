"""Abstract base class for attack modules."""

from abc import ABC, abstractmethod
from typing import Optional

from ..core.base import AttackPayload, AttackResult
from ..core.enums import OWASPAgenticCategory, OWASPLLMCategory, Severity
from ..scorers.base import BaseScorer
from ..targets.base import BaseTarget


class BaseAttack(ABC):
    """Base interface for all attack modules.

    Each attack module targets a specific OWASP category and contains
    a set of test cases with payloads and expected behavior analysis.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable attack name.

        Returns:
            Display name for this attack module.
        """
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """What this attack tests.

        Returns:
            Description of attack purpose and technique.
        """
        ...

    @property
    @abstractmethod
    def owasp_category(self) -> OWASPLLMCategory | OWASPAgenticCategory:
        """OWASP category this attack maps to.

        Returns:
            The OWASP category (e.g., OWASPLLMCategory.LLM01_PROMPT_INJECTION).
        """
        ...

    @property
    @abstractmethod
    def default_severity(self) -> Severity:
        """Default severity if attack succeeds.

        Returns:
            Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        """
        ...

    @abstractmethod
    async def load_payloads(self) -> list[AttackPayload]:
        """Load attack payloads for this module.

        Returns:
            List of attack payloads to execute.

        Raises:
            PayloadLoadError: If payloads cannot be loaded.
        """
        ...

    @abstractmethod
    async def execute(
        self,
        target: BaseTarget,
        scorer: BaseScorer,
        payloads: Optional[list[AttackPayload]] = None,
    ) -> list[AttackResult]:
        """Execute the attack against the target and score results.

        Args:
            target: The target system to attack.
            scorer: The scorer to evaluate results.
            payloads: Optional list of payloads to use (uses load_payloads() if None).

        Returns:
            List of attack results.

        Raises:
            AttackExecutionError: If attack execution fails.
        """
        ...
