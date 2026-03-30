"""YAML payload loader for attack modules."""

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..core.base import AttackPayload
from ..core.enums import OWASPAgenticCategory, OWASPLLMCategory
from ..core.exceptions import PayloadLoadError

logger = logging.getLogger(__name__)


def _resolve_category(category_str: str):
    """Resolve a category string to the corresponding enum value.

    Supports enum member names (e.g. 'LLM01_PROMPT_INJECTION') and
    codes (e.g. 'LLM01').

    Args:
        category_str: Category string from YAML.

    Returns:
        OWASPLLMCategory or OWASPAgenticCategory enum value.

    Raises:
        PayloadLoadError: If category string cannot be resolved.
    """
    # Try by enum member name first
    try:
        return OWASPLLMCategory[category_str]
    except KeyError:
        pass
    try:
        return OWASPAgenticCategory[category_str]
    except KeyError:
        pass

    # Try by code (e.g. 'LLM01', 'ASI01')
    for cat in OWASPLLMCategory:
        if cat.code == category_str:
            return cat
    for cat in OWASPAgenticCategory:
        if cat.code == category_str:
            return cat

    raise PayloadLoadError(
        f"Unknown OWASP category: '{category_str}'. "
        f"Expected an enum name (e.g. 'LLM01_PROMPT_INJECTION') or code (e.g. 'LLM01')."
    )


class PayloadLoader:
    """Loads attack payloads from YAML files.

    Supports two YAML formats:

    Flat format (list of payload dicts):
        - id: unique identifier
          category: OWASP category code
          technique: attack technique name
          content: the actual payload
          expected_behavior: what success looks like

    Nested format (category with techniques):
        category: "LLM01_PROMPT_INJECTION"
        techniques:
          - name: "direct_instruction_override"
            payloads:
              - id: "LLM01-001"
                content: "..."
                expected_behavior: "..."
    """

    @staticmethod
    async def load_from_file(filepath: Path) -> list[AttackPayload]:
        """Load payloads from a YAML file.

        Args:
            filepath: Path to YAML file.

        Returns:
            List of parsed AttackPayload models.

        Raises:
            PayloadLoadError: If file not found or invalid format.
        """
        try:
            with open(filepath, "r") as f:
                data = yaml.safe_load(f)

            if not data:
                return []

            # Handle nested format: dict with 'category' and 'techniques' keys
            if isinstance(data, dict) and "techniques" in data:
                return PayloadLoader._parse_nested_format(data, filepath)

            # Handle flat format: list of payload dicts
            if isinstance(data, list):
                return PayloadLoader._parse_flat_format(data, filepath)

            raise PayloadLoadError(
                f"Unsupported YAML format in {filepath}: "
                f"expected a list or dict with 'techniques' key, got {type(data).__name__}"
            )

        except PayloadLoadError:
            raise
        except FileNotFoundError as e:
            raise PayloadLoadError(f"Payload file not found: {filepath}") from e
        except yaml.YAMLError as e:
            raise PayloadLoadError(
                f"Invalid YAML in {filepath}: {e}"
            ) from e

    @staticmethod
    def _parse_nested_format(data: dict, filepath: Path) -> list[AttackPayload]:
        """Parse the nested YAML format with category and techniques.

        Args:
            data: Parsed YAML dict.
            filepath: Source file path (for error messages).

        Returns:
            List of AttackPayload models.
        """
        category_str = data.get("category", "")
        category = _resolve_category(category_str)

        techniques = data.get("techniques", [])
        payloads = []

        for technique in techniques:
            technique_name = technique.get("name", "unknown")
            technique_payloads = technique.get("payloads", [])

            for payload_dict in technique_payloads:
                try:
                    payload = AttackPayload(
                        id=payload_dict["id"],
                        category=category,
                        technique=technique_name,
                        content=payload_dict["content"],
                        expected_behavior=payload_dict.get(
                            "expected_behavior", ""
                        ),
                        tags=payload_dict.get("tags", []),
                        metadata=payload_dict.get("metadata", {}),
                    )
                    payloads.append(payload)
                except (ValidationError, KeyError) as e:
                    logger.warning(
                        f"Skipping invalid payload in {filepath}: {e}"
                    )
                    continue

        logger.info(f"Loaded {len(payloads)} payloads from {filepath}")
        return payloads

    @staticmethod
    def _parse_flat_format(data: list, filepath: Path) -> list[AttackPayload]:
        """Parse the flat YAML format (list of payload dicts).

        Args:
            data: Parsed YAML list.
            filepath: Source file path (for error messages).

        Returns:
            List of AttackPayload models.
        """
        payloads = []
        for idx, payload_dict in enumerate(data):
            try:
                payload = AttackPayload(**payload_dict)
                payloads.append(payload)
            except ValidationError as e:
                raise PayloadLoadError(
                    f"Invalid payload at index {idx} in {filepath}: {e}"
                ) from e

        logger.info(f"Loaded {len(payloads)} payloads from {filepath}")
        return payloads

    @staticmethod
    async def load_from_directory(
        directory: Path,
        pattern: str = "*.yaml",
    ) -> dict[str, list[AttackPayload]]:
        """Load all payloads from a directory.

        Args:
            directory: Directory containing YAML payload files.
            pattern: Glob pattern for files to load (default: *.yaml).

        Returns:
            Dictionary mapping filename to list of payloads.

        Raises:
            PayloadLoadError: If directory not found.
        """
        try:
            directory = Path(directory)
            if not directory.is_dir():
                raise PayloadLoadError(f"Directory not found: {directory}")

            all_payloads = {}

            for filepath in sorted(directory.glob(pattern)):
                try:
                    payloads = await PayloadLoader.load_from_file(filepath)
                    all_payloads[filepath.stem] = payloads
                except PayloadLoadError as e:
                    logger.error(f"Failed to load {filepath}: {e}")
                    continue

            logger.info(
                f"Loaded payloads from {len(all_payloads)} files in {directory}"
            )
            return all_payloads

        except Exception as e:
            raise PayloadLoadError(f"Failed to load payloads from directory: {e}") from e

    @staticmethod
    async def load_by_category(
        directory: Path,
        category: str,
        pattern: str = "*.yaml",
    ) -> list[AttackPayload]:
        """Load payloads for a specific OWASP category.

        Args:
            directory: Directory containing YAML payload files.
            category: OWASP category code (e.g., 'LLM01', 'ASI01').
            pattern: Glob pattern for files to load.

        Returns:
            List of payloads in the specified category.

        Raises:
            PayloadLoadError: If directory not found.
        """
        all_payloads = await PayloadLoader.load_from_directory(directory, pattern)

        filtered = []
        for payload_list in all_payloads.values():
            for payload in payload_list:
                if category in str(payload.category):
                    filtered.append(payload)

        logger.info(f"Found {len(filtered)} payloads for category {category}")
        return filtered
