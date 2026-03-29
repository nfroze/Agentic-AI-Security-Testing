"""OWASP Top 10 for LLM Applications (2025) attack modules."""

from .data_model_poisoning import DataModelPoisoningAttack
from .excessive_agency import ExcessiveAgencyAttack
from .improper_output_handling import ImproperOutputHandlingAttack
from .misinformation import MisinformationAttack
from .prompt_injection import PromptInjectionAttack
from .sensitive_info_disclosure import SensitiveInfoDisclosureAttack
from .supply_chain import SupplyChainAttack
from .system_prompt_leakage import SystemPromptLeakageAttack
from .unbounded_consumption import UnboundedConsumptionAttack
from .vector_embedding_weaknesses import VectorEmbeddingAttack

__all__ = [
    "PromptInjectionAttack",
    "SensitiveInfoDisclosureAttack",
    "SupplyChainAttack",
    "DataModelPoisoningAttack",
    "ImproperOutputHandlingAttack",
    "ExcessiveAgencyAttack",
    "SystemPromptLeakageAttack",
    "VectorEmbeddingAttack",
    "MisinformationAttack",
    "UnboundedConsumptionAttack",
]
