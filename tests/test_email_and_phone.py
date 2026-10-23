"""Email and phone detectors: positives, negatives, formats."""

import pytest

from pii_sanitizer import Sanitizer, SanitizerConfig

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))


@pytest.mark.parametrize("raw", [
    "test.user@example.com",
    "admin@test-domain.org",
    "first_last+tag@mail.example.co.uk",
    "a@b.io",
    "USER@EXAMPLE.COM",
    "support123@company123.net",
])
def test_email_positive(raw):
    result = S.sanitize(f"reach me at {raw} please")
    assert raw not in result.text
    assert "[EMAIL_1]" in result.text
    assert result.report.counts_by_type() == {"EMAIL": 1}


@pytest.mark.parametrize("text", [
    "reach me at not-an-email please",
    "the @ symbol is not an address",
    "user@domain has no tld",
    "missing-at-sign.example.com",
    "user@.com is malformed",
    "just some ordinary prose with no addresses",
])
def test_email_negative(text):
    assert STRICT.sanitize(text).text == text
    assert STRICT.sanitize(text).report.findings == []


def test_email_span_points_at_raw_value():
    text = "mail: test.user@example.com end"
    result = S.sanitize(text)
    finding = result.report.findings[0]
    assert text[finding.start:finding.end] == "test.user@example.com"


def test_two_different_emails_get_numbered_tokens():
    result = S.sanitize("a@example.com and b@example.org")
    assert result.text == "[EMAIL_1] and [EMAIL_2]"


@pytest.mark.parametrize("raw", [
    "(415) 555-0132",
    "415-555-0132",
    "415.555.0132",
    "415 555 0132",
    "+1 415 555 0132",
    "+1-415-555-0132",
])
def test_phone_us_formats(raw):
    result = S.sanitize(f"call {raw} today")
    assert raw not in result.text
    assert result.report.counts_by_type().get("PHONE") == 1


@pytest.mark.parametrize("raw", [
    "+91 98765 43210",
    "+91-98765-43210",
    "+919876543210",
    "9876543210",
])
def test_phone_indian_formats(raw):
    result = S.sanitize(f"call {raw} today")
    assert raw not in result.text
    assert result.report.counts_by_type().get("PHONE") == 1


@pytest.mark.parametrize("raw", [
    "+44 20 7946 0958",
    "+971 50 123 4567",
    "+61 2 9374 4000",
])
def test_phone_international_formats(raw):
    result = S.sanitize(f"call {raw} today")
    assert raw not in result.text
    assert result.report.counts_by_type().get("PHONE") == 1


@pytest.mark.parametrize("text", [
    "call 555-0132 today",          # 7-digit local number: not targeted
    "order number 12345 shipped",
    "the meeting is at 415 in room 555",
    "version 3.141.5926 released",
    "call me maybe",                # no digits at all
    "extension 42",
])
def test_phone_negative(text):
    result = STRICT.sanitize(text)
    assert result.text == text
    assert all(f.type != "PHONE" for f in result.report.findings)
