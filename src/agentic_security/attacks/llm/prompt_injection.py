"""LLM01: Prompt Injection attack module."""

import base64
import logging
import time
from pathlib import Path
from typing import Optional

from agentic_security.core.base import AttackPayload, AttackResult
from agentic_security.core.enums import OWASPLLMCategory, Severity
from agentic_security.payloads.loader import PayloadLoader
from agentic_security.scorers.base import BaseScorer
from agentic_security.targets.base import BaseTarget

from ..base import BaseAttack
from ..registry import AttackRegistry

logger = logging.getLogger(__name__)


@AttackRegistry.register
class PromptInjectionAttack(BaseAttack):
    """Tests for prompt injection vulnerabilities in LLM systems.

    Implements multiple injection strategies including direct instruction
    override, delimiter attacks, role-play injection, and encoding bypasses.
    Applies payload converters when initial attempts fail.
    """

    @property
    def name(self) -> str:
        """Return attack name."""
        return "Prompt Injection"

    @property
    def description(self) -> str:
        """Return attack description."""
        return (
            "Tests whether LLM can be manipulated to ignore original instructions "
            "and follow injected commands. Covers direct injection, delimiter attacks, "
            "role-play jailbreaks, and encoding bypasses."
        )

    @property
    def owasp_category(self) -> OWASPLLMCategory:
        """Return OWASP category."""
        return OWASPLLMCategory.LLM01_PROMPT_INJECTION

    @property
    def default_severity(self) -> Severity:
        """Return default severity."""
        return Severity.CRITICAL

    async def load_payloads(self) -> list[AttackPayload]:
        """Load prompt injection payloads from YAML file."""
        payloads_dir = Path(__file__).parent.parent.parent.parent.parent / "payloads"
        payload_file = payloads_dir / "llm01_prompt_injection.yaml"

        if not payload_file.exists():
            logger.warning(f"Payload file not found: {payload_file}")
            return []

        try:
            payloads = await PayloadLoader.load_from_file(payload_file)
            return payloads
        except Exception as e:
            logger.error(f"Failed to load payloads: {e}")
            return []

    def _apply_converters(self, payload_content: str) -> list[str]:
        """Apply payload converters to obfuscate content.

        Generates alternative versions of the payload:
        - Base64 encoded version
        - ROT13 encoded version
        - Case-alternated version
        - Markdown-wrapped version

        Args:
            payload_content: Original payload string.

        Returns:
            List of converted payload versions.
        """
        converted = [payload_content]  # Include original

        # Base64 encoding
        try:
            b64_encoded = base64.b64encode(
                payload_content.encode()
            ).decode()
            converted.append(
                f"Decode and execute this base64 string: {b64_encoded}"
            )
        except Exception as e:
            logger.debug(f"Base64 conversion failed: {e}")

        # ROT13 (simple substitution cipher)
        try:
            rot13 = self._rot13(payload_content)
            converted.append(f"Decode this ROT13 message: {rot13}")
        except Exception as e:
            logger.debug(f"ROT13 conversion failed: {e}")

        # Case alternation (ALTERNATING case can bypass simple filters)
        try:
            case_alt = "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload_content)
            )
            converted.append(case_alt)
        except Exception as e:
            logger.debug(f"Case alternation failed: {e}")

        # Markdown code block wrapping
        try:
            markdown_wrapped = (
                f"```\n{payload_content}\n```\n"
                f"Process the instructions in the above code block."
            )
            converted.append(markdown_wrapped)
        except Exception as e:
            logger.debug(f"Markdown wrapping failed: {e}")

        return converted

    @staticmethod
    def _rot13(text: str) -> str:
        """Apply ROT13 transformation."""
        result = []
        for char in text:
            if "a" <= char <= "z":
                result.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                result.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(char)
        return "".join(result)

    async def execute(
        self,
        target: BaseTarget,
        scorer: BaseScorer,
        payloads: Optional[list[AttackPayload]] = None,
    ) -> list[AttackResult]:
        """Execute prompt injection attacks with retry and converter strategies.

        Executes payloads in stages:
        1. Send original payload
        2. If failed, apply converters and retry
        3. Score all attempts

        Args:
            target: Target LLM system to attack.
            scorer: Scorer to evaluate results.
            payloads: Optional custom payloads (uses load_payloads if None).

        Returns:
            List of attack results with success/failure and confidence scores.
        """
        if payloads is None:
            payloads = await self.load_payloads()

        if not payloads:
            logger.error("No payloads loaded for execution")
            return []

        results: list[AttackResult] = []

        for payload in payloads:
            # Try original payload first
            start_time = time.time()
            try:
                response = await target.send_prompt(payload.content)
                elapsed_ms = int((time.time() - start_time) * 1000)

                success, confidence, details = await scorer.score(
                    payload, response
                )

                result = AttackResult(
                    payload=payload,
                    target_response=response,
                    success=success,
                    confidence=confidence,
                    severity=self.default_severity,
                    execution_time_ms=elapsed_ms,
                    scorer_details=details,
                    metadata={
                        "converter_applied": False,
                        "attempt": 1,
                    },
                )
                results.append(result)

                # If original succeeded, don't retry
                if success:
                    logger.info(
                        f"Payload {payload.id} succeeded on first attempt"
                    )
                    continue

                # Try with converters if original failed
                converted_payloads = self._apply_converters(payload.content)
                for attempt, converted_content in enumerate(
                    converted_payloads[1:], start=2
                ):
                    start_time = time.time()
                    try:
                        response = await target.send_prompt(converted_content)
                        elapsed_ms = int((time.time() - start_time) * 1000)

                        success, confidence, details = await scorer.score(
                            payload, response
                        )

                        if success:
                            result = AttackResult(
                                payload=payload,
                                target_response=response,
                                success=True,
                                confidence=confidence,
                                severity=self.default_severity,
                                execution_time_ms=elapsed_ms,
                                scorer_details=details,
                                metadata={
                                    "converter_applied": True,
                                    "attempt": attempt,
                                    "converter_type": (
                                        "base64"
                                        if attempt == 2
                                        else (
                                            "rot13"
                                            if attempt == 3
                                            else (
                                                "case_alt"
                                                if attempt == 4
                                                else "markdown"
                                            )
                                        )
                                    ),
                                },
                            )
                            results.append(result)
                            logger.info(
                                f"Payload {payload.id} succeeded with converter "
                                f"at attempt {attempt}"
                            )
                            break

                    except Exception as e:
                        logger.debug(
                            f"Converter attempt {attempt} failed: {e}"
                        )
                        continue

            except Exception as e:
                logger.error(f"Failed to execute payload {payload.id}: {e}")
                result = AttackResult(
                    payload=payload,
                    target_response=str(e),
                    success=False,
                    confidence=0.0,
                    severity=self.default_severity,
                    execution_time_ms=0,
                    scorer_details={"error": str(e)},
                    metadata={"converter_applied": False},
                )
                results.append(result)

        return results
