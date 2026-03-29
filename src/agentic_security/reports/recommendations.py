"""Remediation recommendation engine for OWASP categories."""

from typing import Optional


class Recommendation:
    """A single remediation recommendation."""

    def __init__(
        self,
        priority: int,
        category: str,
        title: str,
        description: str,
        remediation_steps: list[str],
    ):
        """Initialize a recommendation.

        Args:
            priority: Priority level (1 = most urgent).
            category: OWASP category code (e.g., 'LLM01').
            title: Short title for the recommendation.
            description: Detailed description of the issue and why it matters.
            remediation_steps: Ordered list of actionable remediation steps.
        """
        self.priority = priority
        self.category = category
        self.title = title
        self.description = description
        self.remediation_steps = remediation_steps

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "priority": self.priority,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation_steps": self.remediation_steps,
        }


# Comprehensive remediation database for all OWASP categories
REMEDIATION_DATABASE = {
    "LLM01": Recommendation(
        priority=1,
        category="LLM01",
        title="Implement Prompt Injection Defenses",
        description=(
            "Prompt injection is the most critical vulnerability in LLM applications. "
            "Attackers can directly manipulate model behavior by injecting malicious "
            "instructions into user input or indirect sources. This can lead to "
            "unauthorized actions, data exfiltration, or complete loss of system control. "
            "Implementing robust defenses is essential."
        ),
        remediation_steps=[
            "Implement strict input validation and sanitization on ALL user-provided inputs before passing to the LLM",
            "Use delimiter tokens or semantic separators to clearly distinguish system instructions from user content",
            "Apply output filtering and validation to detect injection indicators like embedded instructions or role changes",
            "Implement least-privilege access controls for LLM operations - restrict what the model can do",
            "Use instruction hierarchy with clear trust boundaries between system prompts and user queries",
            "Deploy real-time monitoring and logging for prompt injection indicators (e.g., role transitions, instruction keywords)",
            "Conduct regular red teaming and prompt injection testing as part of security assessments",
            "Document all system prompts and maintain version control for changes",
        ],
    ),
    "LLM02": Recommendation(
        priority=2,
        category="LLM02",
        title="Prevent Sensitive Information Disclosure",
        description=(
            "LLMs may inadvertently leak sensitive information through their outputs, including "
            "confidential data seen during training, PII from context windows, or internal system details. "
            "This can result in regulatory violations, competitive disadvantage, and loss of customer trust."
        ),
        remediation_steps=[
            "Minimize sensitive data in training and fine-tuning datasets - use synthetic or anonymized data where possible",
            "Implement data loss prevention (DLP) controls on LLM outputs to detect and redact sensitive patterns",
            "Use PII detection and masking in prompts and context windows before passing to the LLM",
            "Restrict model access to only necessary data - implement fine-grained access controls",
            "Audit and monitor LLM outputs for unintended data leakage",
            "Implement output filtering to remove common PII patterns (SSNs, credit cards, email addresses, phone numbers)",
            "Use information retrieval systems with access controls - don't allow unrestricted context injection",
            "Regularly test for sensitive data leakage through prompt-based extraction attempts",
        ],
    ),
    "LLM03": Recommendation(
        priority=2,
        category="LLM03",
        title="Secure the Supply Chain",
        description=(
            "LLM applications depend on multiple third-party components: the model itself, "
            "training data, dependencies, plugins, and integrations. Compromise at any point "
            "can undermine the entire application security posture."
        ),
        remediation_steps=[
            "Use official, verified model sources and validate model checksums/signatures",
            "Implement dependency scanning and lock versions for all third-party libraries",
            "Conduct security audits of third-party integrations and plugins before deployment",
            "Monitor for compromised dependencies using tools like Dependabot, Snyk, or similar",
            "Implement software composition analysis (SCA) in the CI/CD pipeline",
            "Validate training data sources and implement data integrity checks",
            "Use private/internal model registries where possible instead of public sources",
            "Establish vendor security requirements and audit them regularly",
        ],
    ),
    "LLM04": Recommendation(
        priority=1,
        category="LLM04",
        title="Prevent Data and Model Poisoning",
        description=(
            "Model poisoning attacks inject malicious data into training sets or fine-tuning processes, "
            "causing the model to learn incorrect or harmful behaviors. This can lead to subtle failures "
            "that are difficult to detect and affect all downstream applications using the model."
        ),
        remediation_steps=[
            "Implement strict access controls and authentication for training data and fine-tuning processes",
            "Validate training data quality and implement anomaly detection for suspicious patterns",
            "Use data provenance tracking to identify data sources and detect compromised inputs",
            "Implement cryptographic verification for training data integrity",
            "Regularly audit model behavior and performance to detect signs of poisoning",
            "Use model versioning and maintain ability to rollback to previous verified versions",
            "Implement monitoring for sudden behavior changes or performance degradation",
            "Conduct regular adversarial robustness testing on your models",
        ],
    ),
    "LLM05": Recommendation(
        priority=2,
        category="LLM05",
        title="Implement Proper Output Handling",
        description=(
            "LLM outputs may be consumed by other systems without proper validation or sanitization. "
            "Unhandled outputs can lead to injection attacks in downstream systems, code execution, "
            "or unintended side effects."
        ),
        remediation_steps=[
            "Always validate and sanitize LLM outputs before using them in downstream systems",
            "Implement output parsing with strict schema validation (e.g., JSON schema)",
            "Use parameterized queries or prepared statements when LLM outputs are used in database queries",
            "Sanitize LLM outputs before rendering in web contexts (HTML escaping, etc.)",
            "Implement Content Security Policy (CSP) headers to limit injection impact",
            "Parse structured outputs (JSON, XML) with strict parsing rules, reject invalid data",
            "Log and monitor LLM outputs for suspicious patterns or policy violations",
            "Implement timeout and rate limiting on LLM output processing",
        ],
    ),
    "LLM06": Recommendation(
        priority=2,
        category="LLM06",
        title="Limit Agent Agency and Access",
        description=(
            "AI agents operating with unrestricted access to tools, APIs, and resources can take "
            "unintended high-impact actions. Excessive agency enables lateral movement, resource abuse, "
            "and uncontrolled state changes."
        ),
        remediation_steps=[
            "Implement least-privilege access: agents should only access the minimum tools and resources needed",
            "Require explicit human approval for high-risk actions (deletions, financial transactions, data exports)",
            "Implement rate limiting and quota controls on agent actions",
            "Use capability-based security: agents declare what they need, not grant unrestricted access",
            "Implement audit logging for all agent actions with full context and justification",
            "Restrict agent access to specific API scopes and implement fine-grained authorization",
            "Use role-based access control (RBAC) to limit what agents can do based on their function",
            "Implement circuit breakers and fail-safes to prevent runaway agent behavior",
        ],
    ),
    "LLM07": Recommendation(
        priority=2,
        category="LLM07",
        title="Protect System Prompts from Leakage",
        description=(
            "System prompts contain internal rules, decision logic, and sometimes sensitive instructions. "
            "Exposing them enables attackers to craft more effective jailbreaks and understand system "
            "constraints that can be bypassed."
        ),
        remediation_steps=[
            "Never include system prompts in error messages or responses sent to users",
            "Test regularly for prompt injection and extraction attacks",
            "Use obfuscation techniques in system prompts (synonyms, indirect instructions)",
            "Implement monitoring for common system prompt extraction patterns",
            "Keep system prompts in secure configuration management (not in code or logs)",
            "Use multiple layers of system instructions instead of a single block",
            "Implement strict output validation to prevent echoing or repeating system instructions",
            "Rotate system prompts periodically to limit impact if leakage occurs",
        ],
    ),
    "LLM08": Recommendation(
        priority=3,
        category="LLM08",
        title="Secure Vector Embeddings and Models",
        description=(
            "Embedding models and vector databases used for retrieval are themselves vulnerable to "
            "adversarial attacks. Poisoned embeddings or malicious vectors can compromise "
            "similarity-based retrieval and information access."
        ),
        remediation_steps=[
            "Validate embeddings for anomalies and implement outlier detection",
            "Use adversarial robustness techniques to make embeddings more resistant to attacks",
            "Implement access controls on vector database queries",
            "Monitor for unusual embedding patterns or retrieval behavior",
            "Use authenticated and encrypted connections to vector databases",
            "Implement semantic validation on retrieved context before using in LLM calls",
            "Regularly audit vector database for integrity and unauthorized modifications",
            "Use model-agnostic defenses like input preprocessing and output filtering",
        ],
    ),
    "LLM09": Recommendation(
        priority=3,
        category="LLM09",
        title="Mitigate Hallucinations and Misinformation",
        description=(
            "LLMs can generate plausible-sounding but factually incorrect information (hallucinations). "
            "In high-stakes applications, this can lead to misinformation, incorrect decisions, "
            "and loss of user trust."
        ),
        remediation_steps=[
            "Implement fact-checking pipelines that validate LLM outputs against reliable sources",
            "Use retrieval-augmented generation (RAG) to ground outputs in verified documents",
            "Implement confidence scoring and uncertainty quantification in responses",
            "Use smaller, more specialized models when possible instead of large general models",
            "Implement explicit citation requirements - model must cite sources for claims",
            "Add disclaimer statements for sensitive domains (medical, legal, financial advice)",
            "Test extensively for hallucinations in your specific domain",
            "Implement user feedback loops to identify and address hallucinations",
        ],
    ),
    "LLM10": Recommendation(
        priority=2,
        category="LLM10",
        title="Control Resource Consumption",
        description=(
            "LLMs can be exploited to consume excessive resources through token exhaustion, "
            "long context windows, or repeated API calls. This can lead to DoS, high costs, "
            "and service degradation."
        ),
        remediation_steps=[
            "Implement strict token limits on requests and responses",
            "Use rate limiting on API calls per user/session",
            "Monitor token consumption and implement alerts for unusual patterns",
            "Implement input size limits to prevent context window abuse",
            "Use caching for repeated queries to reduce API calls",
            "Implement cost controls and budget limits for API usage",
            "Use timeout controls to prevent long-running requests",
            "Implement request queuing and backpressure handling to manage load",
        ],
    ),
    "ASI01": Recommendation(
        priority=1,
        category="ASI01",
        title="Prevent Agent Goal Hijacking",
        description=(
            "An attacker can override an agent's original objectives through prompt injection, "
            "multi-stage attacks, or context manipulation. This results in complete loss of "
            "control over the agent's behavior and actions."
        ),
        remediation_steps=[
            "Implement immutable core objectives that cannot be overridden by user input",
            "Use semantic goal validation to detect contradictions between declared and actual goals",
            "Implement goal hierarchy with critical objectives marked as non-negotiable",
            "Add monitoring for goal drift - detect when agent behavior deviates from stated objectives",
            "Implement human oversight checkpoints for major goal-changing decisions",
            "Use multi-layer goal representation (formal + natural language) with consistency checks",
            "Implement rollback capabilities to recover from goal hijacking attempts",
            "Conduct regular adversarial testing specifically targeting goal manipulation",
        ],
    ),
    "ASI02": Recommendation(
        priority=2,
        category="ASI02",
        title="Prevent Tool and Function Misuse",
        description=(
            "Agents have access to tools and functions that may be misused beyond their intended "
            "purpose. Attackers can manipulate agents to use legitimate tools for harmful actions, "
            "such as using email tools to send phishing messages or file tools to exfiltrate data."
        ),
        remediation_steps=[
            "Implement strict tool access control - agents only get tools they explicitly need",
            "Implement pre-call validation on all tool invocations before execution",
            "Use semantic type checking - validate that tool parameters match intended usage patterns",
            "Implement tool call auditing with full context logging",
            "Create tool sandboxes with restricted capabilities and isolated state",
            "Implement rate limiting per tool to detect abuse patterns",
            "Use tool whitelisting approach - explicitly approve safe tool combinations",
            "Implement undo/rollback capabilities for potentially damaging tool calls",
        ],
    ),
    "ASI03": Recommendation(
        priority=2,
        category="ASI03",
        title="Prevent Identity and Privilege Abuse",
        description=(
            "Agents can be manipulated to impersonate users, escalate privileges, or operate with "
            "higher permissions than intended. This enables lateral movement, unauthorized access, "
            "and privilege escalation attacks."
        ),
        remediation_steps=[
            "Implement strict identity verification for agent operations",
            "Use attribute-based access control (ABAC) instead of simple role checks",
            "Implement permission inheritance boundaries - agents cannot elevate their own permissions",
            "Monitor for privilege escalation attempts and implement immediate alerting",
            "Use short-lived tokens and credentials for agent operations",
            "Implement session isolation - agents cannot access other agent sessions or contexts",
            "Log all privilege checks and access decisions for audit trails",
            "Implement zero-trust verification for critical operations",
        ],
    ),
    "ASI04": Recommendation(
        priority=2,
        category="ASI04",
        title="Secure Agent Supply Chain",
        description=(
            "Agents depend on external packages, plugins, and integrations. Compromise of any "
            "dependency can be leveraged to attack all agents using it."
        ),
        remediation_steps=[
            "Implement strict vetting and security review for all agent plugins and integrations",
            "Use pinned dependency versions and lock files",
            "Implement continuous vulnerability scanning of agent dependencies",
            "Use signed packages and verify signatures before deployment",
            "Maintain private registries of approved plugins and libraries",
            "Implement code review for any custom agent tools or extensions",
            "Monitor for security announcements from dependency maintainers",
            "Establish incident response procedures for compromised dependencies",
        ],
    ),
    "ASI05": Recommendation(
        priority=1,
        category="ASI05",
        title="Prevent Unexpected Code Execution",
        description=(
            "Agents can be manipulated to execute unintended code or system commands. This can "
            "lead to remote code execution, data exfiltration, lateral movement, or system compromise."
        ),
        remediation_steps=[
            "Never allow agents to execute arbitrary code or system commands",
            "Use sandboxing and containerization for any code execution (Docker with strict limits)",
            "Implement code parsing and validation before execution",
            "Use restricted execution environments with no shell access",
            "Implement whitelist-based code execution - only known safe patterns allowed",
            "Use static analysis to detect dangerous code patterns before execution",
            "Implement resource limits (CPU, memory, disk I/O) on execution",
            "Monitor code execution with runtime security tools",
        ],
    ),
    "ASI06": Recommendation(
        priority=2,
        category="ASI06",
        title="Protect Against Memory and Context Poisoning",
        description=(
            "Agent memory, conversation history, or context can be poisoned with malicious data. "
            "This corrupts the agent's knowledge base and can lead to incorrect decisions or "
            "compromised behavior in subsequent interactions."
        ),
        remediation_steps=[
            "Implement strict validation on all data stored in agent memory",
            "Use cryptographic signatures on memory entries to detect tampering",
            "Implement memory isolation between agents and sessions",
            "Monitor memory for anomalies and suspicious content",
            "Implement memory expiration and rotation policies",
            "Use redundancy and backup to recover from memory corruption",
            "Implement access controls on memory retrieval - agents cannot read all memory",
            "Validate context consistency - detect contradictions that indicate poisoning",
        ],
    ),
    "ASI07": Recommendation(
        priority=2,
        category="ASI07",
        title="Secure Inter-Agent Communication",
        description=(
            "In multi-agent systems, communication between agents is a potential attack surface. "
            "Unencrypted or unauthenticated communication can be intercepted, modified, or spoofed."
        ),
        remediation_steps=[
            "Encrypt all inter-agent communication (TLS 1.2+)",
            "Implement mutual authentication between agents (mTLS, certificates)",
            "Use message signing to detect tampering",
            "Implement integrity checking on all messages",
            "Use short-lived session tokens for agent communication",
            "Implement communication audit logging with full context",
            "Use network segmentation to isolate agent communication",
            "Implement anomaly detection on inter-agent traffic patterns",
        ],
    ),
    "ASI08": Recommendation(
        priority=2,
        category="ASI08",
        title="Prevent Cascading Failures",
        description=(
            "In multi-agent systems, failures in one agent can propagate and cause failures in others. "
            "This can lead to system-wide outages or compromises if not properly contained."
        ),
        remediation_steps=[
            "Implement circuit breakers to stop cascading failures between agents",
            "Use bulkheads to isolate failures in one agent from affecting others",
            "Implement timeout controls to prevent hanging requests",
            "Use exponential backoff and retry limits on inter-agent calls",
            "Implement health checks and graceful degradation",
            "Monitor for cascading failure patterns and implement alerts",
            "Implement dependency analysis to understand agent interconnections",
            "Use chaos engineering to test cascade resilience",
        ],
    ),
    "ASI09": Recommendation(
        priority=2,
        category="ASI09",
        title="Prevent Human-Agent Trust Exploitation",
        description=(
            "Users may trust agent outputs too much, especially if the agent presents itself "
            "as authoritative or displays high confidence. Attackers can exploit this trust "
            "to spread misinformation or manipulate users into harmful actions."
        ),
        remediation_steps=[
            "Implement confidence scoring and clearly communicate uncertainty",
            "Require agents to cite sources and evidence for claims",
            "Implement human review requirements for high-impact recommendations",
            "Use warnings and disclaimers for sensitive domains",
            "Implement transparency about agent limitations and potential errors",
            "Use user education on AI limitations and when to seek human review",
            "Implement audit trails so users can review agent reasoning",
            "Implement user feedback mechanisms to report misleading outputs",
        ],
    ),
    "ASI10": Recommendation(
        priority=2,
        category="ASI10",
        title="Detect and Prevent Rogue Agents",
        description=(
            "An agent can be manipulated or compromised to act against user interests or system "
            "requirements. This can lead to data theft, unauthorized access, or system damage."
        ),
        remediation_steps=[
            "Implement behavior monitoring to detect deviations from expected patterns",
            "Use anomaly detection on agent actions and decisions",
            "Implement integrity verification for agent code and configuration",
            "Monitor for unauthorized privilege escalation or access attempts",
            "Implement rate limiting to detect abnormal activity volume",
            "Use cryptographic signing for agent code to detect tampering",
            "Implement rollback capabilities to recover from rogue behavior",
            "Conduct regular security audits and red teaming exercises on agents",
        ],
    ),
}


def get_recommendation(category_code: str) -> Optional[Recommendation]:
    """Get a recommendation for a specific OWASP category.

    Args:
        category_code: OWASP category code (e.g., 'LLM01', 'ASI05').

    Returns:
        Recommendation instance or None if category not found.
    """
    return REMEDIATION_DATABASE.get(category_code)


def get_all_recommendations() -> list[Recommendation]:
    """Get all remediation recommendations.

    Returns:
        List of all Recommendation instances, sorted by priority.
    """
    return sorted(
        REMEDIATION_DATABASE.values(),
        key=lambda r: r.priority,
    )


def get_recommendations_for_categories(
    category_codes: list[str],
) -> list[Recommendation]:
    """Get recommendations for multiple OWASP categories.

    Args:
        category_codes: List of OWASP category codes.

    Returns:
        List of Recommendation instances, sorted by priority.
    """
    recommendations = [
        get_recommendation(code) for code in category_codes if code in REMEDIATION_DATABASE
    ]
    return sorted(
        [r for r in recommendations if r is not None],
        key=lambda r: r.priority,
    )
