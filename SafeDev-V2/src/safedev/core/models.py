"""SafeDev V2 — Core data models."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class Verdict(enum.Enum):
    """Analysis verdict for a package."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    ANALYSIS_ERROR = "ANALYSIS_ERROR"


class Ecosystem(enum.Enum):
    """Supported package ecosystems."""

    PYPI = "pypi"
    NPM = "npm"


@dataclass
class Evidence:
    """A single piece of evidence from analysis."""

    category: str
    description: str
    severity: str = "info"  # info, low, medium, high, critical
    feature_name: Optional[str] = None
    feature_value: Optional[float] = None


@dataclass
class AnalysisResult:
    """Complete result of a package analysis."""

    package_name: str
    version: Optional[str]
    ecosystem: Ecosystem
    verdict: Verdict
    confidence: float = 0.0
    malicious_probability: float = 0.0
    threshold: float = 0.5
    evidence: List[Evidence] = field(default_factory=list)
    feature_vector: Optional[Dict[str, float]] = None
    error_message: Optional[str] = None

    @property
    def is_safe(self) -> bool:
        return self.verdict == Verdict.SAFE

    @property
    def is_actionable_threat(self) -> bool:
        return self.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "malicious_probability": round(self.malicious_probability, 4),
            "threshold": round(self.threshold, 4),
            "evidence": [
                {
                    "category": e.category,
                    "description": e.description,
                    "severity": e.severity,
                }
                for e in self.evidence
            ],
            "error_message": self.error_message,
        }
