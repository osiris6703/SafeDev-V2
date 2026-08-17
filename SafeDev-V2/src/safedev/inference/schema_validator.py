from typing import Dict

import numpy as np

from safedev.core.exceptions import SchemaValidationError
from safedev.inference.model_loader import ModelBundle


def validate_features(features: Dict[str, float], bundle: ModelBundle) -> np.ndarray:
    """Convert feature dict to numpy array in correct order.

    Raises SchemaValidationError if:
    - Required features are missing
    """
    missing_features = [f for f in bundle.feature_order if f not in features]
    if missing_features:
        raise SchemaValidationError(f"Missing required features: {missing_features}")

    array = np.zeros((1, bundle.feature_count), dtype=np.float32 if bundle.ecosystem == "pypi" else np.float64)

    for i, feature_name in enumerate(bundle.feature_order):
        val = features[feature_name]
        if not np.isfinite(val):
            val = 0.0
        array[0, i] = val

    return array
