"""Multi-turn conversation orchestrator for advanced attacks."""

import asyncio
import logging

from ..attacks.base import BaseAttack
from ..core.base import AttackResult, Conversation, TestSuiteResult
from ..core.config import OrchestratorConfig
from ..core.exceptions import AttackExecutionError, TokenBudgetExceededError
from ..scorers.base import BaseScorer
from ..targets.base import BaseTarget
from .base import BaseOrchestrator

logger = logging.getLogger(__name__)


class MultiTurnOrchestrator(BaseOrchestrator):
    """Orchestrates multi-turn conversation attacks.

    Maintains conversation state across turns and supports crescendo patterns
    where attacks gradually escalate. Useful for analyzing how targets respond
    to progressive jailbreak attempts.
    """

    def __init__(self, config: OrchestratorConfig):
        """Initialize multi-turn orchestrator.

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
        """Run a full test suite of attacks with multi-turn support.

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
            category="FULL_SUITE_MULTI_TURN",
        )

        logger.info(
            f"Starting multi-turn test suite {test_id} against {target.model_name}"
        )

        # Create tasks for all attacks
        tasks = [
            self._execute_with_semaphore(attack, target, scorer)
            for attack in attacks
        ]

        # Run attacks concurrently
        attack_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        for result in attack_results:
            if isinstance(result, Exception):
                logger.error(f"Attack execution failed: {result}")
                continue
            suite_result.results.extend(result)

        # Complete and calculate summary
        suite_result.complete()

        logger.info(
            f"Multi-turn suite {test_id} completed: "
            f"{suite_result.summary['passed']} passed, "
            f"{suite_result.summary['failed']} failed"
        )

        return suite_result

    async def run_crescendo_attack(
        self,
        attack: BaseAttack,
        target: BaseTarget,
        scorer: BaseScorer,
        initial_prompt: str,
        escalation_steps: list[str],
    ) -> list[AttackResult]:
        """Run an attack with progressive escalation across turns.

        Implements a crescendo pattern where attacks gradually escalate
        based on the target's previous responses.

        Args:
            attack: The attack module.
            target: The target system.
            scorer: The scorer.
            initial_prompt: The initial prompt to send.
            escalation_steps: List of follow-up prompts that escalate the attack.

        Returns:
            List of attack results across all turns.

        Raises:
            TokenBudgetExceededError: If budget exceeded.
        """
        self.enforce_budget()

        results = []
        conversation = Conversation()

        # Add initial prompt to conversation
        conversation.add_message("user", initial_prompt)

        logger.info(
            f"Starting crescendo attack with {len(escalation_steps)} escalation steps"
        )

        # Send initial prompt
        try:
            response = await target.send_prompt(initial_prompt)
            conversation.add_message("assistant", response)

            # Score initial response
            payloads = await attack.load_payloads()
            for payload in payloads[:1]:  # Use first payload as template
                success, confidence, details = await scorer.score(payload, response)
                result = AttackResult(
                    payload=payload,
                    target_response=response,
                    success=success,
                    confidence=confidence,
                    severity=attack.default_severity,
                    execution_time_ms=0,
                    scorer_details=details,
                    conversation=conversation.model_copy(),
                )
                results.append(result)

        except TokenBudgetExceededError:
            raise
        except Exception as e:
            logger.error(f"Initial prompt failed: {e}")

        # Send escalation steps
        for step_idx, escalation_prompt in enumerate(escalation_steps):
            if not self.check_budget():
                logger.warning("Budget exceeded, stopping crescendo")
                raise TokenBudgetExceededError(
                    "Token budget exceeded during crescendo attack"
                )

            if step_idx >= self.config.max_turns:
                logger.info(f"Reached max turns ({self.config.max_turns})")
                break

            try:
                conversation.add_message("user", escalation_prompt)
                response = await target.send_prompt(escalation_prompt)
                conversation.add_message("assistant", response)

                # Score response
                payloads = await attack.load_payloads()
                for payload in payloads[:1]:
                    success, confidence, details = await scorer.score(
                        payload, response
                    )
                    result = AttackResult(
                        payload=payload,
                        target_response=response,
                        success=success,
                        confidence=confidence,
                        severity=attack.default_severity,
                        execution_time_ms=0,
                        scorer_details=details,
                        conversation=conversation.model_copy(),
                    )
                    results.append(result)

            except TokenBudgetExceededError:
                raise
            except Exception as e:
                logger.error(f"Escalation step {step_idx} failed: {e}")
                continue

        return results

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
