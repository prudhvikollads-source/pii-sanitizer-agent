"""pii_sanitizer: fail-closed PII redaction library, CLI and agent wrapper."""

from .agent import AgentResult, BlockedPromptError, PromptSanitizerAgent
from .models import (
    ALL_TYPES,
    HIGH_SEVERITY_TYPES,
    Finding,
    Report,
    SanitizeResult,
    SanitizerConfig,
)
from .sanitizer import Sanitizer, sanitize_text

__version__ = "0.1.0"

__all__ = [
    "ALL_TYPES",
    "HIGH_SEVERITY_TYPES",
    "AgentResult",
    "BlockedPromptError",
    "Finding",
    "PromptSanitizerAgent",
    "Report",
    "SanitizeResult",
    "Sanitizer",
    "SanitizerConfig",
    "sanitize_text",
    "__version__",
]
