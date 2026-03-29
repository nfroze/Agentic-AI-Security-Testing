"""Attack module registry with plugin-style auto-discovery."""

import importlib
import pkgutil
from typing import Optional, Type

from .base import BaseAttack


class AttackRegistry:
    """Discovers and manages attack modules.

    Uses plugin-style discovery to find all BaseAttack subclasses
    in the attacks package, enabling modular extensibility.
    """

    _registry: dict[str, Type[BaseAttack]] = {}
    _metadata: dict[str, dict] = {}

    @classmethod
    def register(
        cls,
        attack_class: Type[BaseAttack],
        category: Optional[str] = None,
    ) -> Type[BaseAttack]:
        """Decorator to register an attack module.

        Args:
            attack_class: Attack class to register.
            category: Optional category override for by-category queries.

        Returns:
            The attack class (allows use as @register decorator).
        """
        cls._registry[attack_class.__name__] = attack_class

        # Store metadata for by-category queries
        try:
            instance = attack_class()
            cat = category or str(instance.owasp_category)
            cls._metadata[attack_class.__name__] = {"category": cat}
        except Exception:
            cls._metadata[attack_class.__name__] = {"category": category}

        return attack_class

    @classmethod
    def discover(cls, package_path: str = "agentic_security.attacks") -> None:
        """Auto-discover all attack modules in the package.

        Args:
            package_path: Package path to discover attacks in.
        """
        try:
            package = importlib.import_module(package_path)
        except ImportError:
            return

        for _, module_name, _ in pkgutil.walk_packages(
            package.__path__, prefix=f"{package_path}."
        ):
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseAttack)
                        and attr is not BaseAttack
                    ):
                        cls.register(attr)
            except ImportError:
                continue

    @classmethod
    def get(cls, name: str) -> Type[BaseAttack]:
        """Get attack class by name.

        Args:
            name: Attack class name.

        Returns:
            The attack class.

        Raises:
            KeyError: If attack not found.
        """
        if name not in cls._registry:
            available = list(cls._registry.keys())
            raise KeyError(
                f"Attack '{name}' not found. Available: {available}"
            )
        return cls._registry[name]

    @classmethod
    def list_attacks(cls) -> dict[str, Type[BaseAttack]]:
        """List all registered attacks.

        Returns:
            Dictionary of attack name -> attack class.
        """
        return dict(cls._registry)

    @classmethod
    def get_by_category(cls, category: str) -> list[Type[BaseAttack]]:
        """Get all attacks for a specific OWASP category.

        Args:
            category: OWASP category name or code (e.g., 'LLM01', 'ASI01').

        Returns:
            List of attack classes in that category.
        """
        result = []
        for attack_name, attack_class in cls._registry.items():
            metadata = cls._metadata.get(attack_name, {})
            if metadata.get("category") and category in metadata["category"]:
                result.append(attack_class)
        return result

    @classmethod
    def clear(cls) -> None:
        """Clear the registry (useful for testing)."""
        cls._registry.clear()
        cls._metadata.clear()
