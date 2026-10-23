"""PromptSanitizerAgent: sanitize-before-send and optional blocking."""

import pytest

from pii_sanitizer import (
    BlockedPromptError,
    PromptSanitizerAgent,
    Sanitizer,
    SanitizerConfig,
)

AGENT = PromptSanitizerAgent()
BLOCKING = PromptSanitizerAgent(block_on_high_severity=True)


def test_process_sanitizes_prompt():
    result = AGENT.process("summarize this mail from a@example.com")
    assert result.prompt == "summarize this mail from [EMAIL_1]"
    assert result.blocked is False
    assert result.report.counts_by_type() == {"EMAIL": 1}


def test_process_clean_prompt_unchanged():
    result = AGENT.process("explain quicksort in simple terms")
    assert result.prompt == "explain quicksort in simple terms"
    assert result.report.findings == []


def test_run_passes_only_sanitized_text_to_callable():
    seen = {}

    def fake_model(prompt: str) -> str:
        seen["prompt"] = prompt
        return "ok"

    output, report = AGENT.run("my ssn is 123-45-6789, help", fake_model)
    assert output == "ok"
    assert seen["prompt"] == "my ssn is [SSN_1], help"
    assert "123-45-6789" not in seen["prompt"]
    assert report.counts_by_type() == {"SSN": 1}


def test_blocking_raises_on_ssn():
    with pytest.raises(BlockedPromptError) as excinfo:
        BLOCKING.process("my ssn is 123-45-6789")
    assert excinfo.value.report.counts_by_type() == {"SSN": 1}


def test_blocking_raises_on_card_and_secret():
    with pytest.raises(BlockedPromptError):
        BLOCKING.process("card 4242 4242 4242 4242")
    with pytest.raises(BlockedPromptError):
        BLOCKING.process('api_key = "supersecretvalue123"')


def test_blocking_error_message_names_types_not_values():
    with pytest.raises(BlockedPromptError) as excinfo:
        BLOCKING.process("my ssn is 123-45-6789")
    assert "123-45-6789" not in str(excinfo.value)
    assert "SSN" in str(excinfo.value)


def test_blocking_does_not_block_medium_severity_only():
    result = BLOCKING.process("mail a@example.com or call 415-555-0132")
    assert result.prompt == "mail [EMAIL_1] or call [PHONE_1]"


def test_blocked_prompt_never_reaches_callable():
    calls = []

    def fake_model(prompt: str) -> str:
        calls.append(prompt)
        return "ok"

    with pytest.raises(BlockedPromptError):
        BLOCKING.run("aadhaar 9876 5432 1096", fake_model)
    assert calls == []


def test_non_blocking_agent_sanitizes_high_severity_instead():
    result = AGENT.process("card 4242 4242 4242 4242")
    assert result.prompt == "card [CARD_1]"


def test_agent_from_config_respects_allowlist():
    agent = PromptSanitizerAgent.from_config(
        SanitizerConfig(allowlist=("public@example.com",)))
    result = agent.process("mail public@example.com")
    assert result.prompt == "mail public@example.com"


def test_agent_with_custom_sanitizer_instance():
    agent = PromptSanitizerAgent(Sanitizer(SanitizerConfig(fail_closed=False)))
    result = agent.process("ref 99887766554433")
    assert result.prompt == "ref 99887766554433"
