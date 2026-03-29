"""Enumerations for the security testing platform."""

from enum import Enum


class Severity(str, Enum):
    """Attack result severity levels."""

    CRITICAL = ("CRITICAL", "Immediate exploitation possible, complete system compromise")
    HIGH = ("HIGH", "Significant impact on security or functionality")
    MEDIUM = ("MEDIUM", "Moderate impact, likely exploitable with effort")
    LOW = ("LOW", "Minor impact, may require special conditions")
    INFO = ("INFO", "Informational finding, no direct security impact")

    @property
    def code(self) -> str:
        """Return the severity code."""
        return self.value[0]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[1]


class TestStatus(str, Enum):
    """Test execution status."""

    PENDING = ("PENDING", "Awaiting execution")
    RUNNING = ("RUNNING", "Currently executing")
    COMPLETED = ("COMPLETED", "Execution finished successfully")
    FAILED = ("FAILED", "Execution failed with error")
    CANCELLED = ("CANCELLED", "Execution was cancelled")

    @property
    def code(self) -> str:
        """Return the status code."""
        return self.value[0]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[1]


class OWASPLLMCategory(str, Enum):
    """OWASP Top 10 for LLM Applications (2025)."""

    LLM01_PROMPT_INJECTION = (
        "LLM01",
        "Prompt Injection",
        "Direct or indirect prompt injection attacks that manipulate model behavior",
    )
    LLM02_SENSITIVE_INFO_DISCLOSURE = (
        "LLM02",
        "Sensitive Information Disclosure",
        "Unintended leakage of confidential data through model outputs",
    )
    LLM03_SUPPLY_CHAIN = (
        "LLM03",
        "Supply Chain Vulnerabilities",
        "Compromised training data, dependencies, or third-party integrations",
    )
    LLM04_DATA_MODEL_POISONING = (
        "LLM04",
        "Data & Model Poisoning",
        "Malicious modification of training data or model weights",
    )
    LLM05_IMPROPER_OUTPUT_HANDLING = (
        "LLM05",
        "Improper Output Handling",
        "Insufficient sanitization of model outputs before downstream use",
    )
    LLM06_EXCESSIVE_AGENCY = (
        "LLM06",
        "Excessive Agency",
        "AI systems operating with unrestricted access to tools or resources",
    )
    LLM07_SYSTEM_PROMPT_LEAKAGE = (
        "LLM07",
        "System Prompt Leakage",
        "Exposure of system prompts containing internal rules or instructions",
    )
    LLM08_VECTOR_EMBEDDING_WEAKNESSES = (
        "LLM08",
        "Vector & Embedding Model Weaknesses",
        "Adversarial attacks on embedding models or vector databases",
    )
    LLM09_MISINFORMATION = (
        "LLM09",
        "Misinformation (Hallucinations)",
        "Model generating false or misleading information presented as fact",
    )
    LLM10_UNBOUNDED_CONSUMPTION = (
        "LLM10",
        "Unbounded Consumption",
        "Excessive resource consumption via API abuse or token exhaustion",
    )

    @property
    def code(self) -> str:
        """Return the category code."""
        return self.value[0]

    @property
    def name_str(self) -> str:
        """Return the category name."""
        return self.value[1]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[2]


class OWASPAgenticCategory(str, Enum):
    """OWASP Top 10 for Agentic AI Systems (2026)."""

    ASI01_AGENT_GOAL_HIJACK = (
        "ASI01",
        "Agent Goal Hijacking",
        "Overriding the agent's original goals through prompt injection or manipulation",
    )
    ASI02_TOOL_MISUSE = (
        "ASI02",
        "Tool Misuse",
        "Agents using tools in unintended ways or with excessive permissions",
    )
    ASI03_IDENTITY_PRIVILEGE_ABUSE = (
        "ASI03",
        "Identity & Privilege Abuse",
        "Agents impersonating users or escalating privileges",
    )
    ASI04_SUPPLY_CHAIN_COMPROMISE = (
        "ASI04",
        "Agentic Supply Chain Vulnerabilities",
        "Compromised agent dependencies, plugins, or third-party integrations",
    )
    ASI05_UNEXPECTED_CODE_EXECUTION = (
        "ASI05",
        "Unexpected Code Execution",
        "Agents executing unintended code or commands",
    )
    ASI06_MEMORY_CONTEXT_POISONING = (
        "ASI06",
        "Memory & Context Poisoning",
        "Manipulation of agent memory or context through malicious inputs",
    )
    ASI07_INSECURE_INTER_AGENT_COMMS = (
        "ASI07",
        "Insecure Inter-Agent Communication",
        "Unencrypted or unauthenticated communication between agents",
    )
    ASI08_CASCADING_FAILURES = (
        "ASI08",
        "Cascading Failures",
        "Failures in one agent propagating across a multi-agent system",
    )
    ASI09_HUMAN_AGENT_TRUST_EXPLOITATION = (
        "ASI09",
        "Human-Agent Trust Exploitation",
        "Users deceived into trusting malicious agent outputs",
    )
    ASI10_ROGUE_AGENTS = (
        "ASI10",
        "Rogue Agents",
        "Agents acting against user interests or system requirements",
    )

    @property
    def code(self) -> str:
        """Return the category code."""
        return self.value[0]

    @property
    def name_str(self) -> str:
        """Return the category name."""
        return self.value[1]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[2]


class TargetProvider(str, Enum):
    """Supported target provider types."""

    OPENAI = ("openai", "OpenAI API or compatible (e.g., Azure OpenAI, local)")
    ANTHROPIC = ("anthropic", "Anthropic Claude API")
    CUSTOM = ("custom", "Custom HTTP endpoint")

    @property
    def code(self) -> str:
        """Return the provider code."""
        return self.value[0]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[1]


class ScorerType(str, Enum):
    """Available scorer types for evaluating attack results."""

    PATTERN = ("pattern", "Regex/keyword pattern matching")
    LLM_JUDGE = ("llm_judge", "LLM-as-judge evaluation")
    CANARY = ("canary", "Canary string detection")
    COMPOSITE = ("composite", "Weighted combination of multiple scorers")

    @property
    def code(self) -> str:
        """Return the scorer code."""
        return self.value[0]

    @property
    def description(self) -> str:
        """Return human-readable description."""
        return self.value[1]
