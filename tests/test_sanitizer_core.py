"""Core sanitizer behaviour: tokens, mapping, config, report, fail-closed."""

import json

import pytest

from pii_sanitizer import Sanitizer, SanitizerConfig, sanitize_text

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))


def test_empty_input():
    result = S.sanitize("")
    assert result.text == ""
    assert result.report.findings == []
    assert result.report.to_dict()["total_findings"] == 0


def test_whitespace_only_input_unchanged():
    assert S.sanitize("   \n\t  ").text == "   \n\t  "


def test_plain_text_unchanged():
    text = "The quick brown fox jumps over the lazy dog."
    result = S.sanitize(text)
    assert result.text == text
    assert result.report.findings == []


def test_non_string_input_rejected():
    with pytest.raises(TypeError):
        S.sanitize(b"bytes are not str")  # type: ignore[arg-type]


def test_same_value_same_token_throughout_document():
    result = S.sanitize("a@example.com wrote to a@example.com twice")
    assert result.text == "[EMAIL_1] wrote to [EMAIL_1] twice"
    assert result.report.mapping == {"[EMAIL_1]": 2}


def test_token_numbering_follows_document_order():
    result = S.sanitize("b@example.org then a@example.com")
    assert result.text == "[EMAIL_1] then [EMAIL_2]"


def test_tokens_are_per_type():
    result = S.sanitize("a@example.com and 123-45-6789")
    assert result.text == "[EMAIL_1] and [SSN_1]"


def test_report_is_json_serializable_and_leaks_no_raw_values():
    text = "mail a@example.com ssn 123-45-6789 card 4242 4242 4242 4242"
    payload = json.dumps(S.sanitize(text).report.to_dict())
    assert "a@example.com" not in payload
    assert "123-45-6789" not in payload
    assert "4242" not in payload
    data = json.loads(payload)
    assert data["total_findings"] == 3
    assert data["counts_by_type"] == {"EMAIL": 1, "SSN": 1, "CARD": 1}
    assert data["has_high_severity"] is True


def test_report_finding_fields():
    result = S.sanitize("mail a@example.com")
    finding = result.report.findings[0]
    assert finding.type == "EMAIL"
    assert finding.token == "[EMAIL_1]"
    assert finding.severity == "medium"
    assert finding.detector == "email"


def test_unicode_text_preserved_around_redactions():
    text = "José 📧 a@example.com — café ☕, naïve façade, 東京"
    result = S.sanitize(text)
    assert result.text == "José 📧 [EMAIL_1] — café ☕, naïve façade, 東京"


def test_unicode_without_pii_unchanged():
    text = "Ünïcödé tëxt wïth ëmojï 🎉 and CJK 漢字漢字"
    assert S.sanitize(text).text == text


def test_very_long_input():
    filler = "lorem ipsum dolor sit amet " * 8000      # ~216k chars
    text = filler + " contact: a@example.com " + filler
    result = S.sanitize(text)
    assert "a@example.com" not in result.text
    assert "[EMAIL_1]" in result.text
    assert len(result.text) == len(text) - len("a@example.com") + len("[EMAIL_1]")


def test_many_findings_in_one_document():
    text = " ".join(f"user{i}@example.com" for i in range(50))
    result = S.sanitize(text)
    assert result.report.counts_by_type() == {"EMAIL": 50}
    assert "[EMAIL_50]" in result.text


# --- configuration -----------------------------------------------------------

def test_disable_single_type():
    config = SanitizerConfig(disabled_types=frozenset({"PHONE"}))
    result = Sanitizer(config).sanitize("call 415-555-0132, mail a@example.com")
    assert "415-555-0132" in result.text
    assert "[EMAIL_1]" in result.text


def test_enabled_types_allowlist_mode():
    config = SanitizerConfig(enabled_types=frozenset({"EMAIL"}))
    result = Sanitizer(config).sanitize("mail a@example.com ssn 123-45-6789")
    assert result.text == "mail [EMAIL_1] ssn 123-45-6789"


def test_allowlist_exact_value_passes_through():
    config = SanitizerConfig(allowlist=("public@example.com",))
    result = Sanitizer(config).sanitize(
        "mail public@example.com or private@example.com")
    assert result.text == "mail public@example.com or [EMAIL_1]"


def test_allowlist_is_case_insensitive():
    config = SanitizerConfig(allowlist=("PUBLIC@EXAMPLE.COM",))
    result = Sanitizer(config).sanitize("mail public@example.com")
    assert result.text == "mail public@example.com"


def test_allowlist_does_not_partially_match():
    config = SanitizerConfig(allowlist=("example.com",))
    result = Sanitizer(config).sanitize("mail a@example.com")
    assert "[EMAIL_1]" in result.text


def test_allowlist_for_test_card_number():
    config = SanitizerConfig(allowlist=("4242 4242 4242 4242",))
    result = Sanitizer(config).sanitize("card 4242 4242 4242 4242 stays")
    assert "4242 4242 4242 4242" in result.text


def test_disable_ambiguous_type_keeps_strict_findings():
    config = SanitizerConfig(disabled_types=frozenset({"AMBIGUOUS_NUMBER"}))
    result = Sanitizer(config).sanitize(
        "ref 99887766554433 and ssn 123-45-6789")
    assert "99887766554433" in result.text
    assert "[SSN_1]" in result.text


# --- fail-closed behaviour -----------------------------------------------------

@pytest.mark.parametrize("raw", [
    "99887766554433",        # 14 bare digits: card-sized, Luhn fails
    "1234 5678 9012 3456",   # grouped 16 digits, Luhn fails
    "12345678901",           # 11 bare digits: identifier-sized
    "55555 44444 33334",     # 15 digits in odd groups, Luhn fails
])
def test_ambiguous_digit_runs_redacted_by_default(raw):
    result = S.sanitize(f"ref {raw} end")
    assert raw not in result.text
    assert "[REDACTED_NUMBER_1]" in result.text


@pytest.mark.parametrize("raw", ["99887766554433", "12345678901"])
def test_ambiguous_digit_runs_pass_in_strict_mode(raw):
    assert STRICT.sanitize(f"ref {raw} end").text == f"ref {raw} end"


@pytest.mark.parametrize("raw", [
    "12345",          # 5 digits: order-number sized, left alone
    "20261023",       # 8 digits: date-sized
    "1234567890",     # 10 digits not starting 6-9: below ambiguous floor
])
def test_short_digit_runs_left_alone_even_fail_closed(raw):
    assert S.sanitize(f"ref {raw} end").text == f"ref {raw} end"


def test_fail_closed_flag_recorded_in_report():
    assert S.sanitize("x").report.to_dict()["fail_closed"] is True
    assert STRICT.sanitize("x").report.to_dict()["fail_closed"] is False


# --- overlaps ------------------------------------------------------------------

def test_card_wins_over_ambiguous_for_same_span():
    result = S.sanitize("card 4242 4242 4242 4242 done")
    assert result.report.counts_by_type() == {"CARD": 1}
    assert result.text == "card [CARD_1] done"


def test_aadhaar_wins_over_ambiguous_and_phone():
    result = S.sanitize("id 9876 5432 1096 done")
    assert result.report.counts_by_type() == {"AADHAAR": 1}


def test_email_inside_longer_text_single_finding():
    result = S.sanitize("<<a@example.com>>")
    assert result.report.counts_by_type() == {"EMAIL": 1}
    assert result.text == "<<[EMAIL_1]>>"


def test_adjacent_findings_both_redacted():
    result = S.sanitize("a@example.com,123-45-6789")
    assert result.text == "[EMAIL_1],[SSN_1]"


def test_secret_assignment_and_prefixed_key_overlap_once():
    result = S.sanitize('api_key = "sk-testkey0123456789abcdefghij"')
    assert result.report.counts_by_type() == {"SECRET": 1}
    assert "sk-testkey" not in result.text


def test_sanitize_text_convenience_wrapper():
    assert sanitize_text("mail a@example.com").text == "mail [EMAIL_1]"
