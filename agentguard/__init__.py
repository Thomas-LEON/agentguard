"""
AgentGuard — Security middleware for LangChain agents.

Intercept, validate, and safely execute LLM-generated code
through a 3-layer security pipeline.
"""

from agentguard.exceptions import SecurityBlockedError
from agentguard.policy import SecurityPolicy
from agentguard.sandbox import DockerSandboxExecutor, SandboxUnavailableError
from agentguard.tools.langchain_tool import SafePythonREPLTool

__version__ = "0.2.0"
__all__ = [
    "DockerSandboxExecutor",
    "SandboxUnavailableError",
    "SecurityPolicy",
    "SafePythonREPLTool",
    "SecurityBlockedError",
]
