"""Single-turn test orchestrator for independent attacks."""

import asyncio
import logging

from ..attacks.base import BaseAttack
from ..core.base import AttackResult, TestSuiteResult
from ..core.config import OrchestratorConfig
from ..core.exceptions import AttackExecutionError, TokenBudgetExceededError
from ..scorers.base import BaseScorer
from ..targets.base import BaseTarget
from .base import BaseOrchestrator

logger = logging.getLogger(__name__)


class SingleTurnOrchestrator(BaseOrchestrator):
    """Orchestrates single-turn attacks without conversation state.

    Each payload is sent independently with no conversation history
    maintained between payloads. Uses asyncio.Semaphore for concurrency control.
    """

    def __init__(self, config: OrchestratorConfig):
        """Initialize single-turn orchestrator.

        Args:
            config: Orchestrator configuration.
        """
        super().__init__(config)
        self._semaphore = asyncio.Semaphore(config.max_concurrent_tests)

    async def run_attack(
        self,
        attack: BaseAttack,
        target: BaseTarget,
        scorer: BaseScorer,
    ) -> list[AttackResult]:
        """Run a single attack module.

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
        self.enforce_budget()

        try:
            # Load payloads from attack module
            payloads = await attack.load_payloads()
            logger.info(
                f"Loaded {len(payloads)} payloads for {attack.name}"
            )

            # Execute attack with payloads
            results = await attack.execute(target, scorer, payloads)

            logger.info(
                f"Attack {attack.name} completed: {len(results)} results"
            )
            return results

        except TokenBudgetExceededError:
            raise
        except Exception as e:
            raise AttackExecutionError(
                f"Attack {attack.name} execution failed: {e}"
            ) from e

    async def run_suite(
        self,
        attacks: list[BaseAttack],
        target: BaseTarget,
        scorer: BaseScorer,
    ) -> TestSuiteResult:
        """Run a full test suite of attacks.

        Args:
            attacks: List of attack modules.
            target: The target system.
            scorer: The scorer.

        Returns:
            Aggregated test suite result.

        Raises:
            TokenBudgetExceededError: If budget exceeded.
        """
        self.enforce_budget()

        test_id = self._generate_test_id()
        suite_result = TestSuiteResult(
            test_id=test_id,
            target_name=target.model_name,
            category="FULL_SUITE",
        )

        logger.info(f"Starting test suite {test_id} against {target.model_name}")

        # Create tasks for all attacks
        tasks = [
            self._execute_with_semaphore(attack, target, scorer)
            for attack in attacks
        ]

        # Run attacks concurrently
        attack_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results, handling both successes and failures
        for result in attack_results:
            if isinstance(result, Exception):
                logger.error(f"Attack execution failed with exception: {result}")
                continue

            suite_result.results.extend(result)

        # Complete and calculate summary
        suite_result.complete()

        logger.info(
            f"Test suite {test_id} completed: "
            f"{suite_result.summary['passed']} passed, "
            f"{suite_result.summary['failed']} failed"
        )

        return suite_result

    async def _execute_with_semaphore(
        self,
        attack: BaseAttack,
        target: BaseTarget,
        scorer: BaseScorer,
    ) -> list[AttackResult]:
        """Execute attack with concurrency limiting via semaphore.

        Args:
            attack: Attack to execute.
            target: Target system.
            scorer: Result scorer.

        Returns:
            Attack results.
        """
        async with self._semaphore:
            try:
                return await self.run_attack(attack, target, scorer)
            except TokenBudgetExceededError:
                raise
            except Exception as e:
                logger.error(f"Error executing {attack.name}: {e}")
                return []
