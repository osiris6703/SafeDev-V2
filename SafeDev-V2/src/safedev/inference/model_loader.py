import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

import joblib
import xgboost as xgb

from safedev.core.exceptions import ModelLoadError, ScalerLoadError


@dataclass
class ModelBundle:
    model: Any
    feature_order: List[str]
    feature_count: int
    threshold: float
    scaler: Optional[Any]
    ecosystem: str
    model_card: dict


def load_pypi_model(model_dir: Path) -> ModelBundle:
    """Load PyPI model artifacts."""
    try:
        model_path = model_dir / "model.json"
        feature_order_path = model_dir / "feature_order.txt"
        model_card_path = model_dir / "model_card.json"

        # Load model
        model = xgb.XGBClassifier()
        model.load_model(model_path)

        # Load feature order
        with open(feature_order_path, "r") as f:
            feature_order = [line.strip() for line in f if line.strip()]

        # Load model card
        with open(model_card_path, "r") as f:
            model_card = json.load(f)

        threshold = model_card.get("threshold", {}).get("value", 0.38)

        return ModelBundle(
            model=model,
            feature_order=feature_order,
            feature_count=len(feature_order),
            threshold=threshold,
            scaler=None,
            ecosystem="pypi",
            model_card=model_card,
        )
    except Exception as e:
        raise ModelLoadError(f"Failed to load PyPI model: {e}") from e


def load_npm_model(model_dir: Path) -> ModelBundle:
    """Load npm model artifacts."""
    try:
        model_path = model_dir / "model.joblib"
        scaler_path = model_dir / "scaler.joblib"
        feature_order_path = model_dir / "feature_order.json"
        model_card_path = model_dir / "model_card.json"

        # Ensure sklearn modules are loaded and alias internal _loss for cross-version joblib unpickling
        import sys
        import types
        import sklearn
        import sklearn.ensemble
        import sklearn._loss
        if "_loss" not in sys.modules:
            dummy_loss = types.ModuleType("_loss")
            dummy_loss.CyHalfBinomialLoss = getattr(sklearn._loss, "HalfBinomialLoss", None)
            sys.modules["_loss"] = dummy_loss

        # Load model
        model = joblib.load(model_path)

        # Load feature order
        with open(feature_order_path, "r") as f:
            feature_order = json.load(f)

        # Load model card
        with open(model_card_path, "r") as f:
            model_card = json.load(f)

        threshold = model_card.get("threshold", {}).get("value", 0.13)

    except Exception as e:
        raise ModelLoadError(f"Failed to load npm model: {e}") from e

    try:
        scaler = joblib.load(scaler_path)
    except Exception as e:
        raise ScalerLoadError(f"Failed to load npm scaler: {e}") from e

    return ModelBundle(
        model=model,
        feature_order=feature_order,
        feature_count=len(feature_order),
        threshold=threshold,
        scaler=scaler,
        ecosystem="npm",
        model_card=model_card,
    )
