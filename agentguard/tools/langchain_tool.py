"""
LangChain integration — SafePythonREPLTool.

A drop-in replacement for LangChain's PythonREPLTool that runs
all code through the AgentGuard 3-layer security pipeline before execution.
"""

from typing import Optional, Type

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from agentguard.judges.gemini_judge import SemanticJudge
from agentguard.policy import SecurityPolicy
from agentguard.validators.ast_validator import ASTValidator
from agentguard.validators.network_filter import NetworkFilter


class _CodeInput(BaseModel):
    """Input schema for the SafePythonREPLTool."""

    code: str = Field(description="The Python code to execute.")


class SafePythonREPLTool(BaseTool):
    """
    A secure Python REPL tool for LangChain agents.

    Runs LLM-generated code through AgentGuard's 3-layer security pipeline:
    1. AST Static Validator — blocks forbidden imports and built-in calls.
    2. Network Filter — blocks calls to non-whitelisted domains.
    3. Semantic Judge (optional) — uses Gemini to detect subtle malicious intent.

    If any layer raises a SecurityBlockedError, the error message is returned
    to the agent as tool output, allowing it to self-correct.

    Usage:
        >>> from agentguard import SafePythonREPLTool, SecurityPolicy
        >>> from langchain_google_genai import ChatGoogleGenerativeAI
        >>>
        >>> policy = SecurityPolicy(
        ...     allowed_modules=["pandas", "json"],
        ...     use_semantic_judge=True,
        ... )
        >>> judge_llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
        >>> tool = SafePythonREPLTool(policy=policy, judge_llm=judge_llm)
    """

    name: str = "safe_python_repl"
    description: str = (
        "A secure Python interpreter. Use it to execute Python code. "
        "Dangerous operations (system calls, forbidden imports, data exfiltration) "
        "will be blocked and you will be asked to rewrite the code."
    )
    args_schema: Type[BaseModel] = _CodeInput
    policy: SecurityPolicy = Field(default_factory=SecurityPolicy)
    judge_llm: Optional[BaseChatModel] = None

    def _run(
        self,
        code: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """
        Execute the 3-layer pipeline and run the code if all checks pass.

        Returns a string result (either code output or a SecurityBlockedError
        message for agent self-correction).
        """
        # ── Layer 1: AST Static Analysis ──────────────────────────────────
        ASTValidator(self.policy).validate(code)

        # ── Layer 2: Network Filter ────────────────────────────────────────
        NetworkFilter(self.policy).validate(code)

        # ── Layer 3: Semantic Judge (optional) ────────────────────────────
        if self.policy.use_semantic_judge and self.judge_llm is not None:
            SemanticJudge(self.judge_llm).validate(code)

        # ── All checks passed — execute safely ────────────────────────────
        local_vars: dict = {}
        try:
            exec(code, {"__builtins__": {}}, local_vars)  # noqa: S102
        except Exception as exc:
            return f"Execution error: {exc}"

        output = local_vars.get("result", None)
        return str(output) if output is not None else "Code executed successfully (no result variable set)."
