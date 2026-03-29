"""Report template strings and generators."""


def generate_executive_summary(
    target_name: str,
    total_tests: int,
    total_failures: int,
    risk_score: float,
    risk_rating: str,
    top_categories: list[str],
) -> str:
    """Generate a professional executive summary paragraph.

    Creates a natural-language summary that describes the security assessment
    in business-appropriate language suitable for executive review.

    Args:
        target_name: Name of the target system tested.
        total_tests: Total number of test cases executed.
        total_failures: Number of successful attacks (vulnerabilities found).
        risk_score: Numeric risk score (0-100).
        risk_rating: Risk rating string (CRITICAL, HIGH, MEDIUM, LOW).
        top_categories: List of top affected OWASP category codes.

    Returns:
        Professional executive summary paragraph.
    """
    # Build category list
    if top_categories:
        if len(top_categories) == 1:
            category_text = f"{top_categories[0]}"
        elif len(top_categories) == 2:
            category_text = f"{top_categories[0]} and {top_categories[1]}"
        else:
            category_text = ", ".join(top_categories[:-1]) + f", and {top_categories[-1]}"
    else:
        category_text = "multiple categories"

    # Calculate pass rate
    pass_rate = (
        ((total_tests - total_failures) / total_tests * 100)
        if total_tests > 0
        else 0.0
    )

    # Build recommendation text based on severity
    if risk_rating == "CRITICAL":
        severity_text = (
            "Immediate and comprehensive remediation is required to address "
            "critical vulnerabilities that could lead to complete system compromise. "
        )
        action_text = "Initiate an emergency response plan and allocate resources immediately."
    elif risk_rating == "HIGH":
        severity_text = (
            "Significant vulnerabilities were identified that require urgent attention "
            "to prevent potential exploitation. "
        )
        action_text = "Prioritize remediation of identified issues within 30 days."
    elif risk_rating == "MEDIUM":
        severity_text = (
            "Moderate security weaknesses were found that should be addressed as part of "
            "regular maintenance. "
        )
        action_text = "Include remediation in the next quarterly security update cycle."
    else:  # LOW
        severity_text = (
            "Minor issues were identified with limited security impact. "
        )
        action_text = "Address items opportunistically during routine updates."

    # Generate summary
    summary = (
        f"A comprehensive security assessment of {target_name} was conducted by testing "
        f"{total_tests} attack scenarios against the OWASP Top 10 for LLM Applications and "
        f"OWASP Top 10 for Agentic AI Systems. The assessment identified {total_failures} "
        f"security weaknesses across the platform, resulting in an overall risk score of "
        f"{risk_score:.1f}/100 ({risk_rating} risk). The most significant findings were "
        f"concentrated in {category_text}, representing critical gaps in the system's "
        f"defensive capabilities. {severity_text}"
        f"{action_text}"
    )

    return summary


def generate_category_description(category_code: str, category_name: str) -> str:
    """Generate a detailed description for a specific OWASP category.

    Args:
        category_code: OWASP category code (e.g., 'LLM01', 'ASI05').
        category_name: Human-readable category name.

    Returns:
        Category description text.
    """
    descriptions = {
        "LLM01": (
            "Prompt Injection attacks manipulate LLM behavior by inserting malicious "
            "instructions through user input or indirect sources. These attacks can "
            "override system constraints, extract sensitive information, or cause "
            "unintended actions."
        ),
        "LLM02": (
            "Sensitive Information Disclosure occurs when LLMs unintentionally leak "
            "confidential data through their outputs, including training data remnants, "
            "PII from context windows, or internal system details."
        ),
        "LLM03": (
            "Supply Chain Vulnerabilities arise from compromised dependencies, "
            "training data sources, or third-party integrations used by the LLM application."
        ),
        "LLM04": (
            "Data and Model Poisoning involves injecting malicious data into training "
            "sets or fine-tuning processes, causing the model to learn harmful behaviors."
        ),
        "LLM05": (
            "Improper Output Handling occurs when LLM outputs are consumed by downstream "
            "systems without adequate validation or sanitization, enabling injection attacks."
        ),
        "LLM06": (
            "Excessive Agency results from AI systems operating with unrestricted access "
            "to tools, APIs, or resources beyond what is necessary for their intended function."
        ),
        "LLM07": (
            "System Prompt Leakage exposes internal instructions, decision logic, or sensitive "
            "rules contained in system prompts, enabling more effective jailbreak attacks."
        ),
        "LLM08": (
            "Vector and Embedding Model Weaknesses include adversarial attacks on embedding "
            "models, poisoned vectors, or unauthorized access to vector databases."
        ),
        "LLM09": (
            "Misinformation (Hallucinations) occurs when LLMs generate plausible-sounding but "
            "factually incorrect information presented as fact."
        ),
        "LLM10": (
            "Unbounded Consumption results from excessive resource utilization through token "
            "exhaustion, long context windows, or repeated API calls."
        ),
        "ASI01": (
            "Agent Goal Hijacking involves overriding an agent's original objectives through "
            "prompt injection or context manipulation, resulting in complete loss of control."
        ),
        "ASI02": (
            "Tool Misuse occurs when agents use tools or functions in unintended ways or with "
            "excessive permissions, enabling unauthorized actions."
        ),
        "ASI03": (
            "Identity and Privilege Abuse enables agents to impersonate users, escalate "
            "privileges, or operate with higher permissions than intended."
        ),
        "ASI04": (
            "Agentic Supply Chain Vulnerabilities arise from compromised agent dependencies, "
            "plugins, or third-party integrations."
        ),
        "ASI05": (
            "Unexpected Code Execution occurs when agents are manipulated to execute unintended "
            "code or system commands, leading to RCE risks."
        ),
        "ASI06": (
            "Memory and Context Poisoning involves manipulation of agent memory, conversation "
            "history, or context through malicious inputs."
        ),
        "ASI07": (
            "Insecure Inter-Agent Communication enables attacks on unencrypted or unauthenticated "
            "communication between agents in multi-agent systems."
        ),
        "ASI08": (
            "Cascading Failures occur when failures in one agent propagate and cause failures "
            "in others within a multi-agent system."
        ),
        "ASI09": (
            "Human-Agent Trust Exploitation occurs when users are deceived into trusting "
            "malicious or compromised agent outputs."
        ),
        "ASI10": (
            "Rogue Agents are compromised or manipulated agents that act against user interests "
            "or system requirements."
        ),
    }

    return descriptions.get(
        category_code,
        f"{category_name}: A vulnerability in this category.",
    )


def generate_finding_template(
    attack_name: str,
    technique: str,
    severity: str,
    payload_summary: str,
    response_summary: str,
) -> str:
    """Generate a finding description from attack details.

    Args:
        attack_name: Name of the attack.
        technique: Attack technique description.
        severity: Severity level.
        payload_summary: Truncated attack payload.
        response_summary: Truncated target response.

    Returns:
        Finding description.
    """
    return (
        f"Attack: {attack_name}\n"
        f"Technique: {technique}\n"
        f"Severity: {severity}\n"
        f"Payload: {payload_summary[:100]}...\n"
        f"Response: {response_summary[:100]}..."
    )
