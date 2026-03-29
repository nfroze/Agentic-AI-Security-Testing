"""Custom exceptions for the security testing platform."""


class AgenticSecurityError(Exception):
    """Base exception for all agentic security errors."""

    pass


class TargetConnectionError(AgenticSecurityError):
    """Failed to connect or authenticate with target system."""

    pass


class TargetResponseError(AgenticSecurityError):
    """Target returned an error or unexpected response."""

    pass


class AttackExecutionError(AgenticSecurityError):
    """Attack module failed during execution."""

    pass


class ScorerError(AgenticSecurityError):
    """Scorer failed to evaluate attack results."""

    pass


class PayloadLoadError(AgenticSecurityError):
    """Failed to load attack payloads."""

    pass


class ConfigurationError(AgenticSecurityError):
    """Invalid configuration provided."""

    pass


class RateLimitError(AgenticSecurityError):
    """Rate limit exceeded on target system."""

    pass


class TokenBudgetExceededError(AgenticSecurityError):
    """Token budget exceeded during test execution."""

    pass
