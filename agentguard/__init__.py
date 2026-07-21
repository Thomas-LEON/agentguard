"""
AgentGuard — Security middleware for LangChain agents.

Intercept, validate, and safely execute LLM-generated code
through a 3-layer security pipeline.
"""

from agentguard.exceptions import SecurityBlockedError
from agentguard.policy import SecurityPolicy
from agentguard.tools.langchain_tool import SafePythonREPLTool

__version__ = "0.1.0"
__all__ = ["SecurityPolicy", "SafePythonREPLTool", "SecurityBlockedError"]
