"""SafeDev V2 — Configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def _default_model_dir() -> Path:
    """Resolve model_artifacts directory relative to package root."""
    # SafeDev-V2/model_artifacts/
    return Path(__file__).resolve().parents[3] / "model_artifacts"


@dataclass
class SafetyLimits:
    """Resource limits for safe archive extraction."""

    max_total_extracted_bytes: int = 250 * 1024 * 1024  # 250 MB
    max_single_file_bytes: int = 25 * 1024 * 1024       # 25 MB
    max_python_source_bytes: int = 10 * 1024 * 1024     # 10 MB (PyPI)
    max_source_file_bytes: int = 5 * 1024 * 1024        # 5 MB (npm)
    max_files_per_package: int = 10_000
    max_path_depth: int = 50


@dataclass
class SafeDevConfig:
    """Top-level SafeDev configuration."""

    model_dir: Path = None  # type: ignore[assignment]
    safety_limits: SafetyLimits = None  # type: ignore[assignment]

    # Verdict thresholds — gray zone between safe and malicious
    suspicious_threshold: float = 0.20

    def __post_init__(self):
        if self.model_dir is None:
            self.model_dir = _default_model_dir()
        if self.safety_limits is None:
            self.safety_limits = SafetyLimits()

    @property
    def pypi_model_dir(self) -> Path:
        return self.model_dir / "pypi"

    @property
    def npm_model_dir(self) -> Path:
        return self.model_dir / "npm"
