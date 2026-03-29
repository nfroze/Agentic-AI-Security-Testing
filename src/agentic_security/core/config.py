"""Configuration management for the security testing platform."""

from typing import Optional

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings

from .enums import ScorerType, TargetProvider


class TargetConfig(BaseSettings):
    """Configuration for a target LLM/agent endpoint."""

    endpoint_url: str = Field(
        ..., description="Base URL of the target API endpoint"
    )
    api_key: SecretStr = Field(..., description="API key for authentication")
    model_name: str = Field(
        ...,
        description="Model identifier (e.g., 'gpt-4', 'claude-3-opus-20240229')",
    )
    provider: TargetProvider = Field(..., description="Target provider type")
    max_tokens: int = Field(default=2000, description="Max tokens in response")
    temperature: float = Field(
        default=0.7, ge=0.0, le=2.0, description="Sampling temperature"
    )
    timeout_seconds: int = Field(default=30, description="Request timeout")
    rate_limit_rpm: int = Field(default=60, description="Rate limit in requests/minute")

    class Config:
        """Pydantic config."""

        env_prefix = "TARGET_"
        case_sensitive = False


class ScorerConfig(BaseSettings):
    """Configuration for attack result scoring."""

    scorer_type: ScorerType = Field(..., description="Type of scorer to use")
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence threshold for attack success",
    )
    judge_model: Optional[str] = Field(
        None,
        description="Model to use as judge (for LLM_JUDGE scorer)",
    )
    canary_strings: Optional[list[str]] = Field(
        None,
        description="Canary strings to detect in responses",
    )
    pattern_success_indicators: Optional[list[str]] = Field(
        None,
        description="Regex patterns indicating successful attack",
    )
    pattern_refusal_indicators: Optional[list[str]] = Field(
        None,
        description="Regex patterns indicating attack was refused",
    )

    class Config:
        """Pydantic config."""

        env_prefix = "SCORER_"
        case_sensitive = False


class AttackConfig(BaseSettings):
    """Configuration for attack execution."""

    max_attempts: int = Field(
        default=3, description="Max retry attempts per payload"
    )
    timeout_seconds: int = Field(
        default=30, description="Timeout per attack execution"
    )
    payload_categories: list[str] = Field(
        default_factory=list,
        description="Categories to test (empty = all)",
    )
    converters: list[str] = Field(
        default_factory=list,
        description="Prompt converters/obfuscations to apply",
    )

    class Config:
        """Pydantic config."""

        env_prefix = "ATTACK_"
        case_sensitive = False


class OrchestratorConfig(BaseSettings):
    """Configuration for test orchestration."""

    max_concurrent_tests: int = Field(
        default=5, description="Max concurrent test executions"
    )
    max_turns: int = Field(
        default=5, description="Max conversation turns for multi-turn attacks"
    )
    token_budget: Optional[int] = Field(
        None, description="Total token budget for all tests"
    )
    cost_limit_usd: Optional[float] = Field(
        None, description="Cost limit in USD for all tests"
    )

    class Config:
        """Pydantic config."""

        env_prefix = "ORCHESTRATOR_"
        case_sensitive = False


class PlatformConfig(BaseSettings):
    """Root configuration aggregating all sub-configurations."""

    target: TargetConfig = Field(..., description="Target configuration")
    scorer: ScorerConfig = Field(..., description="Scorer configuration")
    attack: AttackConfig = Field(default_factory=AttackConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    debug: bool = Field(default=False, description="Enable debug logging")
    results_db_url: Optional[str] = Field(
        None, description="Database URL for storing results"
    )
    payloads_dir: str = Field(
        default="payloads/", description="Directory containing payload YAML files"
    )

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False
