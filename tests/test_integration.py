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
    assert output == "4.0"


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
    assert "successfully" in output.lower()
