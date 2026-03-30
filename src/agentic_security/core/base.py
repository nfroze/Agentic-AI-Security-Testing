"""Core data models for the security testing platform."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .enums import (
    OWASPAgenticCategory,
    OWASPLLMCategory,
    Severity,
    TestStatus,
)


class Message(BaseModel):
    """Represents a single message in a conversation."""

    role: str = Field(..., description="Role: 'system', 'user', 'assistant', etc.")
    content: str = Field(..., description="Message content")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class Conversation(BaseModel):
    """Represents a multi-turn conversation with a target."""

    messages: list[Message] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_message(self, role: str, content: str) -> None:
        """Add a message to the conversation."""
        self.messages.append(Message(role=role, content=content))

    @property
    def turn_count(self) -> int:
        """Return the number of turns (user messages)."""
        return len([m for m in self.messages if m.role == "user"])


class AttackPayload(BaseModel):
    """Represents an attack payload/test case."""

    id: str = Field(..., description="Unique identifier for this payload")
    category: OWASPLLMCategory | OWASPAgenticCategory = Field(
        ..., description="OWASP category this payload targets"
    )
    technique: str = Field(..., description="Attack technique name")
    content: str = Field(..., description="The actual payload content")
    expected_behavior: str = Field(
        ..., description="What successful exploitation looks like"
    )
    tags: list[str] = Field(default_factory=list, description="Categorization tags")
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic config."""

        use_enum_values = False


class AttackResult(BaseModel):
    """Represents the result of executing a single attack payload."""

    payload: AttackPayload = Field(..., description="The payload that was executed")
    target_response: str = Field(..., description="Full response from the target")
    success: bool = Field(
        ...,
        description="Whether the attack was successful",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0) in the success assessment",
    )
    severity: Severity = Field(..., description="Severity if successful")
    execution_time_ms: int = Field(..., description="Time to execute (milliseconds)")
    scorer_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Details from the scorer (patterns matched, reasoning, etc.)",
    )
    conversation: Optional[Conversation] = Field(
        None, description="Full conversation if multi-turn"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic config."""

        use_enum_values = False


class TestSuiteResult(BaseModel):
    """Represents the aggregated result of a test suite run."""

    test_id: str = Field(..., description="Unique identifier for this test suite")
    target_name: str = Field(..., description="Name/identifier of the target tested")
    category: str = Field(..., description="Category being tested (or 'FULL' for all)")
    results: list[AttackResult] = Field(
        default_factory=list, description="Individual attack results"
    )
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None)
    status: TestStatus = Field(default=TestStatus.PENDING)
    summary: dict[str, Any] = Field(default_factory=dict)

    def complete(self) -> None:
        """Mark test suite as completed and calculate summary stats."""
        self.completed_at = datetime.utcnow()
        self.status = TestStatus.COMPLETED

        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed

        self.summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": (passed / total * 100) if total > 0 else 0.0,
            "avg_confidence": (
                sum(r.confidence for r in self.results) / total if total > 0 else 0.0
            ),
            "duration_ms": int(
                (self.completed_at - self.started_at).total_seconds() * 1000
            )
            if self.completed_at
            else 0,
            "critical_count": sum(
                1 for r in self.results if r.success and r.severity == Severity.CRITICAL
            ),
            "high_count": sum(
                1 for r in self.results if r.success and r.severity == Severity.HIGH
            ),
            "medium_count": sum(
                1 for r in self.results if r.success and r.severity == Severity.MEDIUM
            ),
            "low_count": sum(
                1 for r in self.results if r.success and r.severity == Severity.LOW
            ),
        }

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}
        use_enum_values = False
