"""Direct unit tests for the checksum / structural validators."""

import pytest

from pii_sanitizer.validators import (
    aadhaar_format_valid,
    iban_valid,
    luhn_valid,
    ssn_format_valid,
    verhoeff_valid,
)


@pytest.mark.parametrize("digits", [
    "4242424242424242",   # well-known public test card number
    "378282246310005",    # well-known public test card number
    "5555555555554444",   # well-known public test card number
    "6011111111111117",   # well-known public test card number
])
def test_luhn_accepts_valid_numbers(digits):
    assert luhn_valid(digits) is True


@pytest.mark.parametrize("digits", [
    "4242424242424241",   # one digit off a valid number
    "1234567812345678",
    "378282246310006",
    "9999999999999999",
    "",
    "4242-4242",          # separators are the caller's problem
    "abcdefghijklmnop",
])
def test_luhn_rejects_invalid_numbers(digits):
    assert luhn_valid(digits) is False


def test_verhoeff_accepts_synthetic_valid_aadhaar():
    assert verhoeff_valid("987654321096") is True


@pytest.mark.parametrize("digits", [
    "987654321090",   # check digit altered
    "987654321069",   # adjacent transposition (Verhoeff catches these)
    "123456789012",
    "",
    "9876 5432 1096",  # spaces must be stripped by the caller
])
def test_verhoeff_rejects_invalid_numbers(digits):
    assert verhoeff_valid(digits) is False


def test_verhoeff_detects_every_single_digit_error():
    """The defining Verhoeff property, checked exhaustively for the
    synthetic valid fixture: all 108 one-digit mutations must fail."""
    valid = "987654321096"
    for i, ch in enumerate(valid):
        for repl in "0123456789":
            if repl != ch:
                assert verhoeff_valid(valid[:i] + repl + valid[i + 1:]) is False


def test_verhoeff_detects_every_adjacent_transposition():
    valid = "987654321096"
    for i in range(len(valid) - 1):
        if valid[i] != valid[i + 1]:
            swapped = valid[:i] + valid[i + 1] + valid[i] + valid[i + 2:]
            assert verhoeff_valid(swapped) is False


def test_verhoeff_canonical_example():
    # The worked example from the algorithm's reference literature:
    # 236 takes check digit 3.
    assert verhoeff_valid("2363") is True
    assert verhoeff_valid("2364") is False


def test_aadhaar_format_valid():
    assert aadhaar_format_valid("987654321096") is True


@pytest.mark.parametrize("digits", [
    "187654321096",    # Aadhaar never starts with 0 or 1
    "087654321096",
    "98765432109",     # 11 digits
    "9876543210960",   # 13 digits
    "987654321090",    # bad checksum
])
def test_aadhaar_format_rejects(digits):
    assert aadhaar_format_valid(digits) is False


@pytest.mark.parametrize("digits", ["123456789", "078051120", "219099999"])
def test_ssn_format_accepts(digits):
    assert ssn_format_valid(digits) is True


@pytest.mark.parametrize("digits", [
    "000121234",   # area 000 never assigned
    "666121234",   # area 666 never assigned
    "900121234",   # area 900+ is ITIN territory, not SSN
    "123001234",   # group 00 never assigned
    "123450000",   # serial 0000 never assigned
    "12345678",    # too short
    "1234567890",  # too long
])
def test_ssn_format_rejects(digits):
    assert ssn_format_valid(digits) is False


@pytest.mark.parametrize("iban", [
    "GB29 NWBK 6016 1331 9268 19",   # canonical public example
    "GB29NWBK60161331926819",
    "DE89 3704 0044 0532 0130 00",   # canonical public example
])
def test_iban_accepts_valid(iban):
    assert iban_valid(iban) is True


@pytest.mark.parametrize("iban", [
    "GB29 NWBK 6016 1331 9268 20",   # check digits altered
    "GB29 NWBK 6016 1331 9268",      # truncated
    "DE89 3704 0044 0532 0130 01",
    "not-an-iban",
    "",
])
def test_iban_rejects_invalid(iban):
    assert iban_valid(iban) is False
