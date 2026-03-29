"""Attack module information endpoints."""

import logging

from fastapi import APIRouter, HTTPException, status

from ...attacks.registry import AttackRegistry
from ...core.enums import OWASPAgenticCategory, OWASPLLMCategory
from ..schemas import AttackModuleResponse, CategoryInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attacks", tags=["attacks"])


@router.get("")
async def list_attacks() -> list[AttackModuleResponse]:
    """List all registered attack modules.

    Returns:
        List of attack module metadata.
    """
    attacks = AttackRegistry.list_attacks()
    responses = []

    for attack_name, attack_class in attacks.items():
        try:
            instance = attack_class()
            responses.append(
                AttackModuleResponse(
                    name=instance.name,
                    description=instance.description,
                    owasp_category=str(instance.owasp_category.name_str),
                    owasp_category_code=instance.owasp_category.code,
                    default_severity=instance.default_severity.code,
                    payload_count=0,  # TODO: Count payloads from load_payloads
                )
            )
        except Exception as e:
            logger.warning(f"Error loading attack {attack_name}: {e}")
            continue

    return responses


@router.get("/categories")
async def list_categories() -> dict[str, list[CategoryInfo]]:
    """List all OWASP categories.

    Returns:
        Dictionary with 'llm' and 'agentic' category lists.
    """
    llm_categories = []
    agentic_categories = []

    # LLM categories
    for cat in OWASPLLMCategory:
        llm_categories.append(
            CategoryInfo(
                code=cat.code,
                name=cat.name_str,
                description=cat.description,
            )
        )

    # Agentic categories
    for cat in OWASPAgenticCategory:
        agentic_categories.append(
            CategoryInfo(
                code=cat.code,
                name=cat.name_str,
                description=cat.description,
            )
        )

    return {
        "llm": llm_categories,
        "agentic": agentic_categories,
    }


@router.get("/{attack_name}")
async def get_attack(attack_name: str) -> AttackModuleResponse:
    """Get details of a specific attack module.

    Args:
        attack_name: Attack module name.

    Returns:
        Attack module details.

    Raises:
        HTTPException: If attack not found.
    """
    try:
        attack_class = AttackRegistry.get(attack_name)
        instance = attack_class()

        return AttackModuleResponse(
            name=instance.name,
            description=instance.description,
            owasp_category=str(instance.owasp_category.name_str),
            owasp_category_code=instance.owasp_category.code,
            default_severity=instance.default_severity.code,
            payload_count=0,  # TODO: Count payloads
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack module '{attack_name}' not found",
        )
    except Exception as e:
        logger.error(f"Error loading attack {attack_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
