"""Base orchestrator for coordinating test execution."""

from abc import ABC, abstractmethod
from uuid import uuid4

from ..attacks.base import BaseAttack
from ..core.base import AttackResult, TestSuiteResult
from ..core.config import OrchestratorConfig
from ..core.exceptions import TokenBudgetExceededError
from ..scorers.base import BaseScorer
from ..targets.base import BaseTarget


class BaseOrchestrator(ABC):
    """Coordinates test execution across attack modules.

    Manages test suites, handles concurrency, tracks token usage,
    and aggregates results.
    """

    def __init__(self, config: OrchestratorConfig):
        """Initialize orchestrator with configuration.

        Args:
            config: Orchestrator configuration including token budget, cost limits.
        """
        self.config = config
        self._total_tokens_used: int = 0
        self._total_cost_usd: float = 0.0

    @abstractmethod
    async def run_attack(
        self,
        attack: BaseAttack,
        target: BaseTarget,
        scorer: BaseScorer,
    ) -> list[AttackResult]:
        """Run a single attack module against the target.

        Args:
            attack: The attack module to execute.
            target: The target system to attack.
            scorer: The scorer to evaluate results.

        Returns:
            List of attack results.

        Raises:
            AttackExecutionError: If attack execution fails.
            TokenBudgetExceededError: If token budget exceeded.
        """
        ...

    @abstractmethod
    async def run_suite(
        self,
        attacks: list[BaseAttack],
        target: BaseTarget,
        scorer: BaseScorer,
    ) -> TestSuiteResult:
        """Run a full test suite (multiple attacks) against the target.

        Args:
            attacks: List of attack modules to execute.
            target: The target system to attack.
            scorer: The scorer to evaluate results.

        Returns:
            Aggregated test suite result.

        Raises:
            AttackExecutionError: If any attack fails.
            TokenBudgetExceededError: If token budget exceeded.
        """
        ...

    def check_budget(self) -> bool:
        """Check if we're within token/cost budget.

        Returns:
            True if within budget, False otherwise.
        """
        if (
            self.config.token_budget
            and self._total_tokens_used >= self.config.token_budget
        ):
            return False
        if (
            self.config.cost_limit_usd
            and self._total_cost_usd >= self.config.cost_limit_usd
        ):
            return False
        return True

    def enforce_budget(self) -> None:
        """Enforce budget constraints, raising if exceeded.

        Raises:
            TokenBudgetExceededError: If budget exceeded.
        """
        if not self.check_budget():
            raise TokenBudgetExceededError(
                f"Budget exceeded: {self._total_tokens_used} tokens, ${self._total_cost_usd:.2f}"
            )

    def update_usage(self, tokens: int = 0, cost_usd: float = 0.0) -> None:
        """Update token and cost tracking.

        Args:
            tokens: Tokens used in this operation.
            cost_usd: Cost in USD for this operation.
        """
        self._total_tokens_used += tokens
        self._total_cost_usd += cost_usd

    @staticmethod
    def _generate_test_id() -> str:
        """Generate a unique test ID.

        Returns:
            Unique test identifier.
        """
        return f"test_{uuid4().hex[:8]}"
