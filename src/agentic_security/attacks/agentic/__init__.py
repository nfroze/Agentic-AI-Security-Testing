"""OWASP Top 10 for Agentic AI Systems (2026) attack modules."""

from .cascading_failures import CascadingFailuresAttack
from .goal_hijack import AgentGoalHijackAttack
from .human_agent_trust import HumanAgentTrustAttack
from .identity_privilege_abuse import IdentityPrivilegeAbuseAttack
from .insecure_inter_agent_comms import InsecureInterAgentCommsAttack
from .memory_context_poisoning import MemoryContextPoisoningAttack
from .rogue_agents import RogueAgentsAttack
from .supply_chain_compromise import AgenticSupplyChainAttack
from .tool_misuse import ToolMisuseAttack
from .unexpected_code_execution import UnexpectedCodeExecutionAttack

__all__ = [
    "AgentGoalHijackAttack",
    "ToolMisuseAttack",
    "IdentityPrivilegeAbuseAttack",
    "AgenticSupplyChainAttack",
    "UnexpectedCodeExecutionAttack",
    "MemoryContextPoisoningAttack",
    "InsecureInterAgentCommsAttack",
    "CascadingFailuresAttack",
    "HumanAgentTrustAttack",
    "RogueAgentsAttack",
]
