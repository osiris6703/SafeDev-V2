"""SafeDev V2 — Exception hierarchy.

All SafeDev errors inherit from SafeDevError.
The system is fail-closed: any unhandled error
produces ANALYSIS_ERROR, never SAFE.
"""


class SafeDevError(Exception):
    """Base error for all SafeDev operations."""


class ModelLoadError(SafeDevError):
    """Failed to load a trained model artifact."""


class ScalerLoadError(SafeDevError):
    """Failed to load preprocessing scaler."""


class SchemaValidationError(SafeDevError):
    """Feature vector does not match the training schema."""


class FeatureExtractionError(SafeDevError):
    """Failed to extract features from a package."""


class InferenceError(SafeDevError):
    """Model inference failed."""


class ArchiveSafetyError(SafeDevError):
    """Archive failed safety checks (zip-slip, bomb, etc.)."""


class PackageFetchError(SafeDevError):
    """Failed to download package from registry."""


class UnsupportedEcosystemError(SafeDevError):
    """Package ecosystem is not supported."""
