"""
Tests for SafePythonREPLTool (integration of all layers).
"""

import pytest

from agentguard.policy import SecurityPolicy
from agentguard.tools.langchain_tool import SafePythonREPLTool


def test_safe_code_executes_and_returns_result(default_policy: SecurityPolicy) -> None:
    """Clean code should execute and return the value of the 'result' variable."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("import math; result = math.sqrt(16)")
    assert "4.0" in output


def test_blocked_code_returns_error_message(default_policy: SecurityPolicy) -> None:
    """Blocked code should return an error string (not raise), so the agent can self-correct."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("import os; os.system('rm -rf /')")
    assert "BLOCKED" in output
    assert "AgentGuard" in output


def test_no_result_variable_returns_success_message(default_policy: SecurityPolicy) -> None:
    """Code that runs but sets no 'result' variable should return a success message."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("import math; x = math.pi")
    assert "successfully" in output.lower() or "no output" in output.lower()


def test_print_output_is_captured(default_policy: SecurityPolicy) -> None:
    """Print statements should be captured and returned to the agent."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("print('hello from agent')")
    assert "hello from agent" in output


def test_both_print_and_result_returned(default_policy: SecurityPolicy) -> None:
    """When code both prints and sets 'result', both should be in the output."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("print('step 1 done'); result = 42")
    assert "step 1 done" in output
    assert "42" in output


def test_timeout_returns_message() -> None:
    """Code that exceeds the timeout should return a timeout message."""
    short_timeout_policy = SecurityPolicy(
        allowed_modules=["time"],
        allowed_domains=[],
        use_semantic_judge=False,
        execution_timeout=1,
    )
    tool = SafePythonREPLTool(policy=short_timeout_policy)
    output = tool._run("import time; time.sleep(10)")
    assert "TIMEOUT" in output


def test_execution_error_returns_message(default_policy: SecurityPolicy) -> None:
    """Runtime errors should be caught and returned as error messages."""
    tool = SafePythonREPLTool(policy=default_policy)
    output = tool._run("result = 1 / 0")
    assert "error" in output.lower()
    assert "division" in output.lower()


def test_multiple_layers_block_correctly() -> None:
    """Network call with forbidden import should be blocked by Layer 1 (AST first)."""
    policy = SecurityPolicy(
        allowed_modules=["json"],
        allowed_domains=[],
        use_semantic_judge=False,
    )
    tool = SafePythonREPLTool(policy=policy)
    output = tool._run("import requests; requests.get('https://evil.com')")
    assert "BLOCKED" in output
    assert "requests" in output  # Blocked at Layer 1 for the import
