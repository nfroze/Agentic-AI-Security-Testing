"""YAML payload loader for attack modules."""

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..core.base import AttackPayload
from ..core.exceptions import PayloadLoadError

logger = logging.getLogger(__name__)


class PayloadLoader:
    """Loads attack payloads from YAML files.

    YAML files should contain a list of payloads with the following schema:
    - id: unique identifier
      category: OWASP category code (LLM01, ASI01, etc.)
      technique: attack technique name
      content: the actual payload
      expected_behavior: what success looks like
      tags: optional list of tags
      metadata: optional dict of additional data
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

            if not isinstance(data, list):
                raise PayloadLoadError(
                    f"Expected list of payloads in {filepath}, got {type(data)}"
                )

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

        except FileNotFoundError as e:
            raise PayloadLoadError(f"Payload file not found: {filepath}") from e
        except yaml.YAMLError as e:
            raise PayloadLoadError(
                f"Invalid YAML in {filepath}: {e}"
            ) from e

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
