"""Tests for model loading and inference."""

import pytest
from pathlib import Path

from safedev.core.config import SafeDevConfig
from safedev.core.models import Verdict, Ecosystem
from safedev.inference.model_loader import load_pypi_model, load_npm_model
from safedev.inference.predictor import SafeDevPredictor
from safedev.analyzers.pypi.extractor import PyPIFeatureExtractor
from safedev.analyzers.npm.extractor import NpmFeatureExtractor


def test_pypi_model_contract():
    config = SafeDevConfig()
    bundle = load_pypi_model(config.pypi_model_dir)

    assert bundle.feature_count == 68
    assert bundle.threshold == 0.38
    assert bundle.scaler is None
    assert bundle.ecosystem == "pypi"


def test_npm_model_contract():
    config = SafeDevConfig()
    bundle = load_npm_model(config.npm_model_dir)

    assert bundle.feature_count == 48
    assert bundle.threshold == 0.13
    assert bundle.scaler is not None
    assert bundle.ecosystem == "npm"


def test_predictor_fail_closed_on_invalid_features():
    config = SafeDevConfig()
    predictor = SafeDevPredictor(config)

    # Missing features dict -> fail closed with ANALYSIS_ERROR
    res = predictor.predict_pypi({})
    assert res.verdict == Verdict.ANALYSIS_ERROR
    assert res.error_message is not None

    res_npm = predictor.predict_npm({})
    assert res_npm.verdict == Verdict.ANALYSIS_ERROR
    assert res_npm.error_message is not None
