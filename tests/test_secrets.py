"""API keys and secret-value detectors."""

import pytest

from pii_sanitizer import Sanitizer, SanitizerConfig

S = Sanitizer()
STRICT = Sanitizer(SanitizerConfig(fail_closed=False))

FAKE_SK = "sk-testkey0123456789abcdefghij"
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"          # documented public example key id
FAKE_GH = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # 36 chars after prefix


@pytest.mark.parametrize("raw", [FAKE_SK, FAKE_AWS, FAKE_GH])
def test_prefixed_keys_positive(raw):
    result = S.sanitize(f"key: {raw}")
    assert result.text == "key: [SECRET_1]"
    assert result.report.findings[0].severity == "high"


@pytest.mark.parametrize("snippet", [
    'api_key = "supersecretvalue123"',
    "api_key: supersecretvalue123",
    "password = hunter2hunter2",
    "passwd: correcthorsebattery",
    'client_secret = "a1b2c3d4e5f6a1b2"',
    "access_token = tok_live_987654321",
    "AUTH_TOKEN=zzzzzzzz99999999",
])
def test_secret_assignment_redacts_value_only(snippet):
    result = S.sanitize(snippet)
    assert "[SECRET_1]" in result.text
    # the key NAME is not itself a secret and stays readable
    assert "=" in result.text or ":" in result.text
    for leaked in ("supersecretvalue123", "hunter2hunter2",
                   "correcthorsebattery", "a1b2c3d4e5f6a1b2",
                   "tok_live_987654321", "zzzzzzzz99999999"):
        assert leaked not in result.text


def test_secret_assignment_span_is_the_value():
    text = 'api_key = "supersecretvalue123"'
    finding = S.sanitize(text).report.findings[0]
    assert text[finding.start:finding.end] == "supersecretvalue123"


def test_bearer_token_redacted():
    result = S.sanitize("Authorization: Bearer abcdefghijklmnopqrstuvwxyz.0123")
    assert "abcdefghijklmnopqrstuvwxyz.0123" not in result.text
    assert "[SECRET_1]" in result.text
    assert "Bearer" in result.text  # scheme word itself is not secret


def test_private_key_header_redacted():
    result = S.sanitize("-----BEGIN PRIVATE KEY-----\nMIIBfakebase64line\n")
    assert "-----BEGIN PRIVATE KEY-----" not in result.text
    assert "[SECRET_1]" in result.text


def test_secrets_in_python_code_snippet():
    code = (
        "import os\n"
        f'KEY = "{FAKE_SK}"\n'
        'password = "hunter2hunter2"\n'
        "print('hello')\n"
    )
    result = S.sanitize(code)
    assert FAKE_SK not in result.text
    assert "hunter2hunter2" not in result.text
    assert "print('hello')" in result.text
    assert result.report.counts_by_type() == {"SECRET": 2}


def test_secrets_in_json_blob():
    blob = '{"api_key": "supersecretvalue123", "user": "sam"}'
    result = S.sanitize(blob)
    assert "supersecretvalue123" not in result.text
    assert '"user": "sam"' in result.text


@pytest.mark.parametrize("text", [
    "the password field is required",     # the word, no assignment
    "passwords must be 12 characters",
    "token = abc",                          # value too short to be a secret
    "api_key is documented elsewhere",
    "sk-short is not a key",                # prefix but far too short
    "AKIA123 is truncated",
    "a monkey and a keyboard",
])
def test_secret_negative(text):
    result = STRICT.sanitize(text)
    assert result.text == text
    assert all(f.type != "SECRET" for f in result.report.findings)


def test_same_secret_twice_same_token():
    result = S.sanitize(f"{FAKE_SK} then again {FAKE_SK}")
    assert result.text == "[SECRET_1] then again [SECRET_1]"
    assert result.report.mapping == {"[SECRET_1]": 2}
