"""SafeDev V2 — Ecosystem resolver.

Detects whether a package is PyPI or npm and resolves identity.
"""

from __future__ import annotations

from safedev.core.exceptions import UnsupportedEcosystemError
from safedev.core.models import Ecosystem


def detect_ecosystem(
    package_name: str,
    *,
    ecosystem_hint: str | None = None,
) -> Ecosystem:
    """Detect or validate the package ecosystem.

    Args:
        package_name: Package name or specifier.
        ecosystem_hint: Explicit ecosystem ('pypi', 'npm', or None).

    Returns:
        Detected Ecosystem enum value.

    Raises:
        UnsupportedEcosystemError: If ecosystem cannot be determined.
    """
    if ecosystem_hint is not None:
        hint_lower = ecosystem_hint.lower().strip()
        if hint_lower in ("pypi", "pip", "python"):
            return Ecosystem.PYPI
        if hint_lower in ("npm", "node", "js", "javascript"):
            return Ecosystem.NPM
        raise UnsupportedEcosystemError(
            f"Unsupported ecosystem: '{ecosystem_hint}'. "
            f"Use 'pypi' or 'npm'."
        )

    # Heuristic detection
    if package_name.startswith("@"):
        # Scoped npm package (@scope/name)
        return Ecosystem.NPM

    # Default to PyPI if no hint provided
    return Ecosystem.PYPI


def parse_package_spec(
    spec: str,
) -> tuple[str, str | None]:
    """Parse a package specifier into (name, version).

    Supports:
        'requests'           -> ('requests', None)
        'requests==2.31.0'   -> ('requests', '2.31.0')
        'requests@2.31.0'    -> ('requests', '2.31.0')
        '@scope/pkg@1.0.0'   -> ('@scope/pkg', '1.0.0')
    """
    # Handle @scope/pkg@version (npm scoped)
    if spec.startswith("@"):
        # Find the second @ which separates version
        second_at = spec.find("@", 1)
        if second_at != -1:
            return spec[:second_at], spec[second_at + 1:]
        return spec, None

    # Handle ==version (PyPI)
    if "==" in spec:
        parts = spec.split("==", 1)
        return parts[0].strip(), parts[1].strip()

    # Handle @version
    if "@" in spec:
        parts = spec.split("@", 1)
        return parts[0].strip(), parts[1].strip()

    return spec.strip(), None
