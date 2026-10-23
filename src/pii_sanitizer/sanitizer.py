"""Core sanitizer: candidates -> overlap resolution -> token replacement."""

from __future__ import annotations

from . import detectors, models
from .models import Finding, Report, SanitizeResult, SanitizerConfig


class Sanitizer:
    """Redact PII from text, fail-closed by default.

    The same raw value always maps to the same replacement token within
    one document (``[EMAIL_1]``), and numbering follows document order,
    so redacted text stays readable and coreference is preserved --
    without keeping the raw values anywhere in the report.
    """

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        self.config = config or SanitizerConfig()

    def _allowlist_spans(self, text: str) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        lowered = text.lower()
        for entry in self.config.allowlist:
            if not entry:
                continue
            needle = entry.lower()
            index = lowered.find(needle)
            while index != -1:
                spans.append((index, index + len(needle)))
                index = lowered.find(needle, index + 1)
        return spans

    def sanitize(self, text: str) -> SanitizeResult:
        if not isinstance(text, str):
            raise TypeError("sanitize() expects str input")
        if text == "":
            return SanitizeResult("", Report(fail_closed=self.config.fail_closed))

        candidates = detectors.all_candidates(text, self.config.fail_closed)
        candidates = [
            c for c in candidates if self.config.is_enabled(c[0])
        ]
        # Allowlist semantics: an allowlisted value is never redacted --
        # including any candidate fully contained inside one of its
        # occurrences (e.g. the 12-digit prefix of an allowlisted card
        # number would otherwise re-match as an Aadhaar-shaped span).
        allow_spans = self._allowlist_spans(text)
        if allow_spans:
            candidates = [
                c for c in candidates
                if not any(a_start <= c[1] and c[2] <= a_end
                           for a_start, a_end in allow_spans)
            ]
        # AMBIGUOUS_NUMBER can be switched off via config like any type,
        # independently of the fail_closed flag which *generates* them.
        chosen = detectors.resolve_overlaps(candidates)

        token_by_value: dict[str, str] = {}
        counters: dict[str, int] = {}
        findings: list[Finding] = []
        pieces: list[str] = []
        cursor = 0
        for finding_type, start, end, detector_name in chosen:
            raw = text[start:end]
            if raw not in token_by_value:
                counters[finding_type] = counters.get(finding_type, 0) + 1
                label = models.TOKEN_LABEL[finding_type]
                token_by_value[raw] = f"[{label}_{counters[finding_type]}]"
            token = token_by_value[raw]
            findings.append(Finding(
                type=finding_type, start=start, end=end, token=token,
                severity=models.SEVERITY[finding_type], detector=detector_name,
            ))
            pieces.append(text[cursor:start])
            pieces.append(token)
            cursor = end
        pieces.append(text[cursor:])

        mapping: dict[str, int] = {}
        for finding in findings:
            mapping[finding.token] = mapping.get(finding.token, 0) + 1
        report = Report(
            findings=findings, mapping=mapping,
            fail_closed=self.config.fail_closed,
        )
        return SanitizeResult("".join(pieces), report)


def sanitize_text(text: str, config: SanitizerConfig | None = None) -> SanitizeResult:
    """Convenience one-shot wrapper around :class:`Sanitizer`."""
    return Sanitizer(config).sanitize(text)
