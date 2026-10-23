"""Agent wrapper: sanitize prompts before they reach an LLM.

The wrapper is transport-agnostic -- it never calls a model itself. It
returns the sanitized prompt plus the redaction report, and the caller
hands the sanitized text to whatever model/client it already uses.

With ``block_on_high_severity=True`` a prompt containing high-severity
PII (SSN, Aadhaar, card, IBAN, passport, secret, or a fail-closed
ambiguous number) is refused outright by raising
:class:`BlockedPromptError`: redaction is the default, refusal is the
escalation for material that should never leave the machine at all.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .models import Report, SanitizerConfig
from .sanitizer import Sanitizer


class BlockedPromptError(Exception):
    """Raised when blocking is enabled and high-severity PII is present.

    Carries the redaction report (which contains spans and tokens only,
    never raw values) so callers can log *what kind* of PII blocked the
    prompt without logging the PII itself.
    """

    def __init__(self, report: Report) -> None:
        types = ", ".join(sorted(report.counts_by_type()))
        super().__init__(
            f"prompt blocked: high-severity PII detected ({types})"
        )
        self.report = report


@dataclass
class AgentResult:
    prompt: str          # the sanitized prompt, safe to send onward
    report: Report
    blocked: bool = False


class PromptSanitizerAgent:
    def __init__(
        self,
        sanitizer: Sanitizer | None = None,
        *,
        block_on_high_severity: bool = False,
    ) -> None:
        self.sanitizer = sanitizer or Sanitizer()
        self.block_on_high_severity = block_on_high_severity

    @classmethod
    def from_config(
        cls, config: SanitizerConfig, *, block_on_high_severity: bool = False
    ) -> "PromptSanitizerAgent":
        return cls(Sanitizer(config), block_on_high_severity=block_on_high_severity)

    def process(self, prompt: str) -> AgentResult:
        """Sanitize *prompt*; raise BlockedPromptError when blocking."""
        result = self.sanitizer.sanitize(prompt)
        if self.block_on_high_severity and result.report.has_high_severity:
            raise BlockedPromptError(result.report)
        return AgentResult(prompt=result.text, report=result.report)

    def run(
        self, prompt: str, llm_callable: Callable[[str], str]
    ) -> tuple[str, Report]:
        """Sanitize, then invoke ``llm_callable`` with the CLEAN prompt.

        The callable is never invoked at all when the prompt is blocked.
        Returns ``(model_output, redaction_report)``.
        """
        processed = self.process(prompt)
        return llm_callable(processed.prompt), processed.report
