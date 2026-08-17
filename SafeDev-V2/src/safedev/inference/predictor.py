"""SafeDev V2 — Inference predictor.

Runs model inference and produces verdicts.
FAIL-CLOSED: Any error returns ANALYSIS_ERROR, never SAFE.
"""

from __future__ import annotations

from typing import Dict, Optional

from safedev.core.config import SafeDevConfig
from safedev.core.models import AnalysisResult, Ecosystem, Evidence, Verdict
from safedev.inference.model_loader import (
    ModelBundle,
    load_npm_model,
    load_pypi_model,
)
from safedev.inference.schema_validator import validate_features


class SafeDevPredictor:
    """Run inference on extracted features.

    Lazy-loads model bundles on first use.
    All errors produce ANALYSIS_ERROR (fail-closed).
    """

    def __init__(self, config: SafeDevConfig):
        self._pypi_bundle: Optional[ModelBundle] = None
        self._npm_bundle: Optional[ModelBundle] = None
        self._config = config

    def predict_pypi(
        self, features: Dict[str, float]
    ) -> AnalysisResult:
        """Predict on PyPI features. XGBoost on RAW features (no scaler)."""
        try:
            if self._pypi_bundle is None:
                self._pypi_bundle = load_pypi_model(
                    self._config.pypi_model_dir
                )

            X = validate_features(features, self._pypi_bundle)

            # XGBoost: predict_proba on RAW features
            prob = float(
                self._pypi_bundle.model.predict_proba(X)[:, 1][0]
            )

            verdict = self._determine_verdict(
                prob, self._pypi_bundle.threshold
            )

            return AnalysisResult(
                package_name="",
                version=None,
                ecosystem=Ecosystem.PYPI,
                verdict=verdict,
                confidence=abs(prob - self._pypi_bundle.threshold),
                malicious_probability=prob,
                threshold=self._pypi_bundle.threshold,
                feature_vector=features,
            )

        except Exception as e:
            return AnalysisResult(
                package_name="",
                version=None,
                ecosystem=Ecosystem.PYPI,
                verdict=Verdict.ANALYSIS_ERROR,
                error_message=str(e),
            )

    def predict_npm(
        self, features: Dict[str, float]
    ) -> AnalysisResult:
        """Predict on npm features. GradientBoosting with StandardScaler."""
        try:
            if self._npm_bundle is None:
                self._npm_bundle = load_npm_model(
                    self._config.npm_model_dir
                )

            X = validate_features(features, self._npm_bundle)

            # npm: apply StandardScaler THEN predict
            if self._npm_bundle.scaler is not None:
                X = self._npm_bundle.scaler.transform(X)

            prob = float(
                self._npm_bundle.model.predict_proba(X)[:, 1][0]
            )

            verdict = self._determine_verdict(
                prob, self._npm_bundle.threshold
            )

            return AnalysisResult(
                package_name="",
                version=None,
                ecosystem=Ecosystem.NPM,
                verdict=verdict,
                confidence=abs(prob - self._npm_bundle.threshold),
                malicious_probability=prob,
                threshold=self._npm_bundle.threshold,
                feature_vector=features,
            )

        except Exception as e:
            return AnalysisResult(
                package_name="",
                version=None,
                ecosystem=Ecosystem.NPM,
                verdict=Verdict.ANALYSIS_ERROR,
                error_message=str(e),
            )

    def _determine_verdict(
        self, probability: float, threshold: float
    ) -> Verdict:
        """Map probability to verdict."""
        if probability >= threshold:
            return Verdict.MALICIOUS
        if probability >= self._config.suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.SAFE
