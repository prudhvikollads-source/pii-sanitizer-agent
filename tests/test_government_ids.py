"""SSN, Aadhaar and passport detectors."""

import pytest

from pii_sanitizer import Sanitizer, SanitizerConfig

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))


# --- SSN -------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["123-45-6789", "078-05-1120", "219-09-9999"])
def test_ssn_positive(raw):
    result = S.sanitize(f"ssn: {raw}")
    assert result.text == "ssn: [SSN_1]"
    assert result.report.findings[0].severity == "high"


@pytest.mark.parametrize("raw", [
    "000-12-3456", "666-12-3456", "900-12-3456",
    "123-00-6789", "123-45-0000",
])
def test_ssn_structurally_invalid_is_not_typed_ssn(raw):
    result = S.sanitize(f"ssn: {raw}")
    assert all(f.type != "SSN" for f in result.report.findings)


@pytest.mark.parametrize("raw", ["000-12-3456", "666-12-3456", "123-00-6789"])
def test_ssn_structurally_invalid_passes_in_strict_mode(raw):
    assert STRICT.sanitize(f"ssn: {raw}").text == f"ssn: {raw}"


@pytest.mark.parametrize("raw", ["000-12-3456", "666-12-3456", "123-45-0000"])
def test_ssn_structurally_invalid_still_redacted_fail_closed(raw):
    """Fail-closed: dashed 3-2-4 shape is redacted even when invalid."""
    result = S.sanitize(f"ssn: {raw}")
    assert raw not in result.text
    assert result.report.counts_by_type() == {"AMBIGUOUS_NUMBER": 1}


def test_ssn_without_dashes_is_not_an_ssn_finding():
    result = STRICT.sanitize("number 123456789 here")
    assert all(f.type != "SSN" for f in result.report.findings)


# --- Aadhaar -----------------------------------------------------------------

VALID_AADHAAR_SPACED = "9876 5432 1096"   # synthetic, Verhoeff-valid
VALID_AADHAAR_BARE = "987654321096"


def test_aadhaar_spaced_positive():
    result = S.sanitize(f"aadhaar: {VALID_AADHAAR_SPACED}")
    assert result.text == "aadhaar: [AADHAAR_1]"


def test_aadhaar_bare_positive():
    result = S.sanitize(f"aadhaar: {VALID_AADHAAR_BARE}")
    assert result.text == "aadhaar: [AADHAAR_1]"


def test_aadhaar_dashed_valid_checksum_but_dashed_form():
    # The dashed rendering of the same synthetic number: grouping is an
    # Aadhaar shape signal, digits validate, so it is typed AADHAAR.
    result = S.sanitize("aadhaar: 9876-5432-1096")
    assert "9876-5432-1096" not in result.text
    assert result.report.counts_by_type().get("AADHAAR") == 1


def test_aadhaar_bad_checksum_not_typed_aadhaar():
    result = S.sanitize("aadhaar: 9876 5432 1090")
    assert all(f.type != "AADHAAR" for f in result.report.findings)


def test_aadhaar_bad_checksum_redacted_fail_closed():
    result = S.sanitize("aadhaar: 9876 5432 1090")
    assert "9876 5432 1090" not in result.text


def test_aadhaar_bad_checksum_passes_in_strict_mode():
    text = "aadhaar: 9876 5432 1090"
    assert STRICT.sanitize(text).text == text


@pytest.mark.parametrize("raw", [
    "1234 5678 9012",   # leading 1: never a valid Aadhaar prefix
    "0234 5678 9012",   # leading 0
])
def test_aadhaar_bad_prefix_not_typed(raw):
    result = S.sanitize(f"id: {raw}")
    assert all(f.type != "AADHAAR" for f in result.report.findings)


@pytest.mark.parametrize("raw", ["9876 5432 109", "9876 5432 10965"])
def test_aadhaar_wrong_length_passes_in_strict_mode(raw):
    assert STRICT.sanitize(f"id: {raw}").text == f"id: {raw}"


# --- Passport ------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["A12345678", "C79403752", "X99999999"])
def test_passport_us_shape_positive(raw):
    result = S.sanitize(f"document {raw} verified")
    assert raw not in result.text
    assert result.report.counts_by_type().get("PASSPORT") == 1


@pytest.mark.parametrize("raw", ["Z1234567", "J8369854"])
def test_passport_indian_shape_positive(raw):
    result = S.sanitize(f"document {raw} verified")
    assert raw not in result.text
    assert result.report.counts_by_type().get("PASSPORT") == 1


def test_passport_context_word_catches_plain_number():
    result = S.sanitize("passport number: 654321 on the form")
    assert "654321" not in result.text
    assert result.report.counts_by_type().get("PASSPORT") == 1


def test_passport_context_span_excludes_the_word_passport():
    text = "passport number: 654321 on the form"
    finding = S.sanitize(text).report.findings[0]
    assert text[finding.start:finding.end] == "654321"


@pytest.mark.parametrize("text", [
    "document a1234567 verified",     # lowercase: not a passport shape
    "order AB12345 shipped",          # two letters + 5 digits
    "the passport office is closed",  # the word alone, no number
    "gate Z12 now boarding",
])
def test_passport_negative(text):
    result = STRICT.sanitize(text)
    assert result.text == text
    assert all(f.type != "PASSPORT" for f in result.report.findings)
