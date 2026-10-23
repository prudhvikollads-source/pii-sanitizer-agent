"""Card (Luhn) and IBAN detectors, including the fail-closed near-miss policy."""

import pytest

from pii_sanitizer import Sanitizer, SanitizerConfig

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))

VALID_CARD_SPACED = "4242 4242 4242 4242"      # public test number
VALID_CARD_BARE = "4242424242424242"
VALID_CARD_AMEX = "378282246310005"            # public test number, 15 digits
INVALID_CARD_SPACED = "4242 4242 4242 4241"    # Luhn fails by one digit


@pytest.mark.parametrize("raw", [
    VALID_CARD_SPACED, VALID_CARD_BARE, VALID_CARD_AMEX,
    "4242-4242-4242-4242", "5555 5555 5555 4444",
])
def test_card_luhn_valid_positive(raw):
    result = S.sanitize(f"card: {raw}")
    assert result.text == "card: [CARD_1]"
    assert result.report.findings[0].detector == "card_luhn"


def test_card_invalid_luhn_is_not_typed_card():
    result = S.sanitize(f"card: {INVALID_CARD_SPACED}")
    assert all(f.type != "CARD" for f in result.report.findings)


def test_card_invalid_luhn_redacted_fail_closed_as_ambiguous():
    """Documented policy: a card-shaped near miss is still redacted."""
    result = S.sanitize(f"card: {INVALID_CARD_SPACED}")
    assert INVALID_CARD_SPACED not in result.text
    assert result.text == "card: [REDACTED_NUMBER_1]"
    assert result.report.findings[0].detector == "card_shape_fail_closed"


def test_card_invalid_luhn_passes_in_strict_mode():
    text = f"card: {INVALID_CARD_SPACED}"
    assert STRICT.sanitize(text).text == text


@pytest.mark.parametrize("raw", [
    "424242424242",        # 12 digits: below card length
    "4242 4242",           # 8 digits
    "12345",               # plain short number
])
def test_short_digit_strings_are_not_cards_in_strict_mode(raw):
    result = STRICT.sanitize(f"num: {raw}")
    assert result.text == f"num: {raw}"


def test_card_embedded_in_sentence_keeps_surrounding_text():
    result = S.sanitize("paid with 4242 4242 4242 4242 on monday")
    assert result.text == "paid with [CARD_1] on monday"


# --- IBAN --------------------------------------------------------------------

VALID_IBAN = "GB29 NWBK 6016 1331 9268 19"     # canonical public example
VALID_IBAN_DE = "DE89 3704 0044 0532 0130 00"  # canonical public example


@pytest.mark.parametrize("raw", [VALID_IBAN, "GB29NWBK60161331926819", VALID_IBAN_DE])
def test_iban_positive(raw):
    result = S.sanitize(f"iban: {raw}")
    assert result.text == "iban: [IBAN_1]"
    assert result.report.findings[0].detector == "iban_mod97"


def test_iban_bad_check_digits_not_typed_iban():
    result = S.sanitize("iban: GB29 NWBK 6016 1331 9268 20")
    assert all(f.type != "IBAN" for f in result.report.findings)


def test_iban_bad_check_digits_redacted_fail_closed():
    result = S.sanitize("iban: GB29 NWBK 6016 1331 9268 20")
    assert "GB29 NWBK 6016 1331 9268 20" not in result.text


def test_iban_bad_check_digits_pass_in_strict_mode():
    text = "iban: GB29 NWBK 6016 1331 9268 20"
    assert STRICT.sanitize(text).text == text


@pytest.mark.parametrize("text", [
    "iban: the reference is pending",
    "code GB12 is a region label",      # too short to be an IBAN
    "flight DE89 departs at noon",      # fragment, not an account number
])
def test_iban_negative(text):
    result = STRICT.sanitize(text)
    assert result.text == text
    assert all(f.type != "IBAN" for f in result.report.findings)
