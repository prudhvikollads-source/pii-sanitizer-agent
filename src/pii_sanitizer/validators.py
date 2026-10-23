"""Checksum and format validators.

Pure standard library. Each validator answers one narrow question about a
candidate string that a detector regex already isolated, so detectors can
stay simple and validators can be unit-tested in isolation.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Luhn (mod-10) checksum, used for payment card numbers.
# ---------------------------------------------------------------------------

def luhn_valid(digits: str) -> bool:
    """Return True when *digits* passes the Luhn checksum.

    Only ASCII digits are accepted; separators must be stripped by the
    caller. Length is not judged here -- that is the detector's job.
    """
    if not digits or not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Verhoeff checksum, used by India's Aadhaar numbering scheme.
# ---------------------------------------------------------------------------

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(digits: str) -> bool:
    """Return True when *digits* passes the Verhoeff checksum."""
    if not digits or not digits.isdigit():
        return False
    checksum = 0
    for index, char in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(char)]]
    return checksum == 0


def aadhaar_format_valid(digits: str) -> bool:
    """Structural Aadhaar rules: 12 digits, first digit 2-9, Verhoeff ok."""
    return (
        len(digits) == 12
        and digits.isdigit()
        and digits[0] in "23456789"
        and verhoeff_valid(digits)
    )


# ---------------------------------------------------------------------------
# SSN structural rules (US SSA assignment rules).
# ---------------------------------------------------------------------------

def ssn_format_valid(digits: str) -> bool:
    """Structural SSN rules for a 9-digit string.

    Area (first 3) may not be 000, 666 or 900-999; group (middle 2) may
    not be 00; serial (last 4) may not be 0000.
    """
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


# ---------------------------------------------------------------------------
# IBAN (ISO 13616) mod-97 check.
# ---------------------------------------------------------------------------

_IBAN_LENGTHS = {
    "DE": 22, "GB": 22, "FR": 27, "IN": 22, "AE": 23, "NL": 18,
    "ES": 24, "IT": 27, "CH": 21, "AU": 0,  # AU has no IBAN; placeholder 0 == unknown
}


def iban_valid(candidate: str) -> bool:
    """Return True when *candidate* is a structurally valid IBAN."""
    compact = re.sub(r"\s+", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    if not (15 <= len(compact) <= 34):
        return False
    expected = _IBAN_LENGTHS.get(compact[:2])
    if expected and len(compact) != expected:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = ""
    for char in rearranged:
        numeric += char if char.isdigit() else str(ord(char) - 55)
    # mod-97 in chunks to keep integers small on any platform.
    remainder = 0
    for i in range(0, len(numeric), 7):
        remainder = int(str(remainder) + numeric[i:i + 7]) % 97
    return remainder == 1
