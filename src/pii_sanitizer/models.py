"""Data model for findings, reports and sanitizer configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

# Finding types (stable strings; they appear verbatim in reports).
EMAIL = "EMAIL"
PHONE = "PHONE"
SSN = "SSN"
AADHAAR = "AADHAAR"
PASSPORT = "PASSPORT"
CARD = "CARD"
IBAN = "IBAN"
SECRET = "SECRET"
AMBIGUOUS_NUMBER = "AMBIGUOUS_NUMBER"

ALL_TYPES = (
    EMAIL, PHONE, SSN, AADHAAR, PASSPORT, CARD, IBAN, SECRET, AMBIGUOUS_NUMBER,
)

# Replacement-token label per type.
TOKEN_LABEL = {
    EMAIL: "EMAIL",
    PHONE: "PHONE",
    SSN: "SSN",
    AADHAAR: "AADHAAR",
    PASSPORT: "PASSPORT",
    CARD: "CARD",
    IBAN: "IBAN",
    SECRET: "SECRET",
    AMBIGUOUS_NUMBER: "REDACTED_NUMBER",
}

SEVERITY = {
    EMAIL: "medium",
    PHONE: "medium",
    SSN: "high",
    AADHAAR: "high",
    PASSPORT: "high",
    CARD: "high",
    IBAN: "high",
    SECRET: "high",
    AMBIGUOUS_NUMBER: "high",
}

HIGH_SEVERITY_TYPES = frozenset(
    t for t, sev in SEVERITY.items() if sev == "high"
)


@dataclass(frozen=True)
class Finding:
    """One detected span. Deliberately carries NO copy of the raw value:
    a report should be safe to log and share on its own."""

    type: str
    start: int
    end: int
    token: str = ""
    severity: str = "medium"
    detector: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "token": self.token,
            "severity": self.severity,
            "detector": self.detector,
        }


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    # token -> count of occurrences replaced with that token in this document
    mapping: dict[str, int] = field(default_factory=dict)
    fail_closed: bool = True

    @property
    def has_high_severity(self) -> bool:
        return any(f.type in HIGH_SEVERITY_TYPES for f in self.findings)

    def counts_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.type] = counts.get(finding.type, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "fail_closed": self.fail_closed,
            "total_findings": len(self.findings),
            "counts_by_type": self.counts_by_type(),
            "has_high_severity": self.has_high_severity,
            "findings": [f.to_dict() for f in self.findings],
            "mapping": dict(self.mapping),
        }


@dataclass
class SanitizeResult:
    text: str
    report: Report

    @property
    def findings(self) -> list[Finding]:
        return self.report.findings


@dataclass(frozen=True)
class SanitizerConfig:
    """Per-type switches, allowlist and the fail-closed policy flag."""

    disabled_types: frozenset[str] = frozenset()
    enabled_types: frozenset[str] | None = None  # None == everything enabled
    allowlist: tuple[str, ...] = ()
    fail_closed: bool = True

    def is_enabled(self, finding_type: str) -> bool:
        if self.enabled_types is not None and finding_type not in self.enabled_types:
            return False
        return finding_type not in self.disabled_types

    def is_allowlisted(self, raw_value: str) -> bool:
        lowered = raw_value.lower()
        return any(lowered == entry.lower() for entry in self.allowlist)
