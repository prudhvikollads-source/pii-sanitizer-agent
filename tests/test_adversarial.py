"""Adversarial and edge cases.

Some tests here intentionally pin CURRENT behaviour on inputs designed
to defeat regex detection. Those are the documented limitations in the
README -- pinning them means a future detector improvement shows up as
a deliberate test change, not a silent behaviour drift.
"""

from pii_sanitizer import Sanitizer, SanitizerConfig

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))


def test_pii_at_very_start_and_end_of_text():
    result = S.sanitize("a@example.com is first, last is 123-45-6789")
    assert result.text == "[EMAIL_1] is first, last is [SSN_1]"


def test_pii_split_across_lines():
    result = S.sanitize("mail:\na@example.com\nssn:\n123-45-6789\n")
    assert "[EMAIL_1]" in result.text
    assert "[SSN_1]" in result.text


def test_repeated_pii_on_many_lines():
    text = "\n".join(["call 415-555-0132"] * 20)
    result = S.sanitize(text)
    assert result.report.mapping == {"[PHONE_1]": 20}
    assert "415-555-0132" not in result.text


def test_html_like_markup_around_email():
    result = S.sanitize('<a href="mailto:a@example.com">mail me</a>')
    assert result.text == '<a href="mailto:[EMAIL_1]">mail me</a>'


def test_markdown_and_punctuation_boundaries():
    result = S.sanitize("Mail **a@example.com**. Or (a@example.com)!")
    assert result.text == "Mail **[EMAIL_1]**. Or ([EMAIL_1])!"


def test_mixed_case_secret_key_name():
    result = S.sanitize('Api_Key = "supersecretvalue123"')
    assert "supersecretvalue123" not in result.text


def test_multiple_secrets_on_one_line():
    result = S.sanitize(
        'api_key = "supersecretvalue123" password = "hunter2hunter2"')
    assert result.report.counts_by_type() == {"SECRET": 2}
    assert "supersecretvalue123" not in result.text
    assert "hunter2hunter2" not in result.text


def test_full_document_mixed_pii():
    text = (
        "From: a@example.com\n"
        "Call +91 98765 43210 about card 4242 4242 4242 4242\n"
        "SSN 123-45-6789, IBAN GB29 NWBK 6016 1331 9268 19\n"
    )
    result = S.sanitize(text)
    for raw in ("a@example.com", "+91 98765 43210", "4242 4242 4242 4242",
                "123-45-6789", "GB29 NWBK 6016 1331 9268 19"):
        assert raw not in result.text
    assert result.report.counts_by_type() == {
        "EMAIL": 1, "PHONE": 1, "CARD": 1, "SSN": 1, "IBAN": 1}


# --- documented limitations (pinned current behaviour) ------------------------

def test_limitation_obfuscated_email_at_dot_not_detected():
    """KNOWN LIMITATION: 'name [at] domain dot com' defeats the email
    regex. Pinned here; see README Limitations. Human review is required
    for deliberately obfuscated addresses."""
    text = "reach me at name [at] example dot com"
    assert STRICT.sanitize(text).text == text


def test_limitation_obfuscated_email_spelled_out_not_detected():
    text = "name at example dot com is my address"
    assert STRICT.sanitize(text).text == text


def test_limitation_spaced_out_ssn_not_detected():
    """KNOWN LIMITATION: digits separated group-by-group with spaces
    ('123 45 6789') match neither the dashed SSN pattern nor the
    11+ digit ambiguous sweep."""
    text = "ssn written out: 123 45 6789"
    assert STRICT.sanitize(text).text == text


def test_limitation_dot_separated_card_not_typed_card():
    """KNOWN LIMITATION: cards written with dot separators are not
    recognised as cards (only spaces/hyphens/contiguous are)."""
    text = "card 4242.4242.4242.4242"
    result = STRICT.sanitize(text)
    assert all(f.type != "CARD" for f in result.report.findings)


def test_limitation_words_for_digits_not_detected():
    text = "my number is one two three four five"
    assert S.sanitize(text).text == text
