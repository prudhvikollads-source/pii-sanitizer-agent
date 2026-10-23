"""Regex detectors plus checksum validators.

Every detector yields candidate spans of the form
``(type, start, end, detector_name)``. Candidates may overlap; the
sanitizer resolves overlaps by priority (secrets and checksum-validated
identifiers win over looser patterns) and by span length.

FAIL-CLOSED POLICY (see README for the full rationale):
  * A grouped digit string shaped like a payment card whose Luhn check
    FAILS is still redacted -- as AMBIGUOUS_NUMBER, not CARD -- because a
    typo'd or partially masked card number is still a card number.
  * A 4-4-4 grouped digit string shaped like an Aadhaar whose Verhoeff
    check fails is still redacted as AMBIGUOUS_NUMBER in fail-closed mode.
  * Any remaining bare or separated digit run totalling 11-19 digits is
    redacted as AMBIGUOUS_NUMBER in fail-closed mode.
  * IBAN-shaped strings that fail mod-97 are redacted as AMBIGUOUS_NUMBER
    in fail-closed mode.
With ``fail_closed=False`` only checksum/structure-valid findings from the
strict detectors are redacted; ambiguous material passes through untouched.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from . import models
from .validators import aadhaar_format_valid, iban_valid, luhn_valid, ssn_format_valid

Candidate = tuple[str, int, int, str]

# Resolution priority: lower wins when spans overlap.
PRIORITY = {
    models.SECRET: 0,
    models.EMAIL: 1,
    models.IBAN: 2,
    models.CARD: 3,
    models.SSN: 4,
    models.AADHAAR: 5,
    models.PASSPORT: 6,
    models.PHONE: 7,
    models.AMBIGUOUS_NUMBER: 9,
}

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")

# Aadhaar: "dddd dddd dddd", "dddd-dddd-dddd" or 12 contiguous digits.
_AADHAAR_GROUPED_RE = re.compile(r"\b([2-9]\d{3})[ ](\d{4})[ ](\d{4})\b")
_AADHAAR_DASHED_RE = re.compile(r"\b([2-9]\d{3})-(\d{4})-(\d{4})\b")
_AADHAAR_BARE_RE = re.compile(r"\b([2-9]\d{11})\b")

# Cards: 13-19 digits, contiguous or grouped in 4s (spaces or hyphens).
_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

_IBAN_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b"
)

_PASSPORT_CONTEXT_RE = re.compile(
    r"(?i:passport\s*(?:no\.?|number|num|#)?\s*[:\-]?\s*)([A-Z0-9]{6,10})\b"
)
_PASSPORT_US_RE = re.compile(r"\b[A-Z]\d{8}\b")      # US: letter + 8 digits
_PASSPORT_IN_RE = re.compile(r"\b[A-Z]\d{7}\b")      # India: letter + 7 digits

_PHONE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Indian mobile with country code: +91 98765 43210 / +91-9876543210
    ("phone_international_in",
     re.compile(r"\+91[\s\-]?[6-9]\d{4}[\s\-]?\d{5}\b")),
    # International E.164-ish: +1 415 555 0132, +44 20 7946 0958, +971 50 123 4567
    ("phone_international",
     re.compile(r"\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{4}\b")),
    # US: (415) 555-0132 / 415-555-0132 / 415.555.0132 / 415 555 0132
    ("phone_us",
     re.compile(r"\(?\b\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b")),
    # Indian mobile, bare 10 digits starting 6-9.
    ("phone_in_mobile", re.compile(r"\b[6-9]\d{9}\b")),
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    # (detector name, pattern, group index holding the secret value; 0 == whole)
    ("secret_prefixed_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), 0),
    ("secret_prefixed_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("secret_prefixed_key", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0),
    ("secret_prefixed_key", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), 0),
    ("secret_prefixed_key", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), 0),
    ("secret_bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-]{20,})"), 1),
    ("secret_private_key_block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0),
    ("secret_assignment",
     re.compile(
         r"(?i)\b(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key|[_-]?token)?"
         r"|password|passwd|pwd|access[_-]?token|auth[_-]?token|client[_-]?secret)"
         r"\b[\"']?\s*[:=]\s*[\"']?([^\s\"'`,;]{8,})[\"']?"
     ), 1),
)

# Any digit run (bare, or separated by single spaces/hyphens) not already
# claimed by a strict detector. Judged purely on total digit count.
_AMBIGUOUS_RE = re.compile(r"\b\d[\d \-]*\d\b|\b\d\b")


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def detect_emails(text: str) -> Iterator[Candidate]:
    for match in _EMAIL_RE.finditer(text):
        yield (models.EMAIL, match.start(), match.end(), "email")


def detect_ssns(text: str, fail_closed: bool) -> Iterator[Candidate]:
    for match in _SSN_RE.finditer(text):
        digits = "".join(match.groups())
        if ssn_format_valid(digits):
            yield (models.SSN, match.start(), match.end(), "ssn")
        elif fail_closed:
            # Dashed 3-2-4 is a strong shape signal; a structurally invalid
            # one is most often a typo'd real SSN. Redact, don't guess.
            yield (models.AMBIGUOUS_NUMBER, match.start(), match.end(),
                   "ssn_shape_fail_closed")


def detect_aadhaar(text: str, fail_closed: bool) -> Iterator[Candidate]:
    seen: set[tuple[int, int]] = set()
    for pattern in (_AADHAAR_GROUPED_RE, _AADHAAR_DASHED_RE, _AADHAAR_BARE_RE):
        for match in pattern.finditer(text):
            span = (match.start(), match.end())
            if span in seen:
                continue
            seen.add(span)
            digits = _digits(match.group(0))
            if aadhaar_format_valid(digits):
                yield (models.AADHAAR, match.start(), match.end(), "aadhaar")
            elif fail_closed:
                yield (models.AMBIGUOUS_NUMBER, match.start(), match.end(),
                       "aadhaar_shape_fail_closed")


def detect_cards(text: str, fail_closed: bool) -> Iterator[Candidate]:
    for match in _CARD_RE.finditer(text):
        digits = _digits(match.group(0))
        if not (13 <= len(digits) <= 19):
            continue
        if luhn_valid(digits):
            yield (models.CARD, match.start(), match.end(), "card_luhn")
        elif fail_closed:
            yield (models.AMBIGUOUS_NUMBER, match.start(), match.end(),
                   "card_shape_fail_closed")


def detect_ibans(text: str, fail_closed: bool) -> Iterator[Candidate]:
    for match in _IBAN_RE.finditer(text):
        if iban_valid(match.group(0)):
            yield (models.IBAN, match.start(), match.end(), "iban_mod97")
        elif fail_closed:
            yield (models.AMBIGUOUS_NUMBER, match.start(), match.end(),
                   "iban_shape_fail_closed")


def detect_passports(text: str) -> Iterator[Candidate]:
    for match in _PASSPORT_CONTEXT_RE.finditer(text):
        # Context alone is not enough: the value must contain a digit,
        # so "passport number: PENDING" is not swept up.
        if not any(ch.isdigit() for ch in match.group(1)):
            continue
        yield (models.PASSPORT, match.start(1), match.end(1),
               "passport_context")
    for pattern, name in ((_PASSPORT_US_RE, "passport_us_shape"),
                          (_PASSPORT_IN_RE, "passport_in_shape")):
        for match in pattern.finditer(text):
            yield (models.PASSPORT, match.start(), match.end(), name)


def detect_phones(text: str) -> Iterator[Candidate]:
    for name, pattern in _PHONE_PATTERNS:
        for match in pattern.finditer(text):
            yield (models.PHONE, match.start(), match.end(), name)


def detect_secrets(text: str) -> Iterator[Candidate]:
    for name, pattern, group in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            yield (models.SECRET, match.start(group), match.end(group), name)


def detect_ambiguous_numbers(text: str) -> Iterator[Candidate]:
    """Fail-closed sweep: 11-19 total digits in one run is identifier-sized."""
    for match in _AMBIGUOUS_RE.finditer(text):
        digits = _digits(match.group(0))
        if 11 <= len(digits) <= 19:
            yield (models.AMBIGUOUS_NUMBER, match.start(), match.end(),
                   "ambiguous_digit_run")


def all_candidates(text: str, fail_closed: bool) -> list[Candidate]:
    candidates: list[Candidate] = []
    candidates.extend(detect_secrets(text))
    candidates.extend(detect_emails(text))
    candidates.extend(detect_ibans(text, fail_closed))
    candidates.extend(detect_cards(text, fail_closed))
    candidates.extend(detect_ssns(text, fail_closed))
    candidates.extend(detect_aadhaar(text, fail_closed))
    candidates.extend(detect_passports(text))
    candidates.extend(detect_phones(text))
    if fail_closed:
        candidates.extend(detect_ambiguous_numbers(text))
    return candidates


def resolve_overlaps(candidates: list[Candidate]) -> list[Candidate]:
    """Greedy non-overlapping selection.

    Order: priority class first, then longer span, then earlier start.
    The winner keeps its exact span; losers are dropped entirely (never
    partially redacted, which would leak the remainder).
    """
    ordered = sorted(
        candidates,
        key=lambda c: (PRIORITY[c[0]], -(c[2] - c[1]), c[1]),
    )
    chosen: list[Candidate] = []
    occupied: list[tuple[int, int]] = []
    for cand in ordered:
        _, start, end, _ = cand
        if any(start < occ_end and occ_start < end
               for occ_start, occ_end in occupied):
            continue
        chosen.append(cand)
        occupied.append((start, end))
    return sorted(chosen, key=lambda c: c[1])
