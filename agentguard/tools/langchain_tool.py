"""
LangChain integration — SafePythonREPLTool.

A drop-in replacement for LangChain's PythonREPLTool that runs
all code through the AgentGuard 3-layer security pipeline before execution.
"""

import io
import sys
import threading
from contextlib import redirect_stdout
from typing import Optional, Type

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from agentguard.exceptions import SecurityBlockedError
from agentguard.judges.gemini_judge import SemanticJudge
from agentguard.policy import SecurityPolicy
from agentguard.validators.ast_validator import ASTValidator
from agentguard.validators.network_filter import NetworkFilter

# Builtins that are safe to expose to LLM-generated code.
# This whitelist explicitly excludes dangerous functions like
# exec, eval, compile, open, __import__, getattr, setattr, delattr.
_SAFE_BUILTINS: dict = {
    # Types & constructors
    "bool": bool,
    "int": int,
    "float": float,
    "str": str,
    "list": list,
    "dict": dict,
    "tuple": tuple,
    "set": set,
    "frozenset": frozenset,
    "bytes": bytes,
    "bytearray": bytearray,
    "complex": complex,
    "type": type,
    # Iteration & ranges
    "range": range,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "reversed": reversed,
    "iter": iter,
    "next": next,
    # Aggregation
    "len": len,
    "min": min,
    "max": max,
    "sum": sum,
    "abs": abs,
    "round": round,
    "sorted": sorted,
    "any": any,
    "all": all,
    # String & representation
    "print": print,
    "repr": repr,
    "format": format,
    "chr": chr,
    "ord": ord,
    "ascii": ascii,
    "hex": hex,
    "oct": oct,
    "bin": bin,
    # Type checking
    "isinstance": isinstance,
    "issubclass": issubclass,
    "callable": callable,
    "hasattr": hasattr,
    # Conversion & introspection
    "id": id,
    "hash": hash,
    "dir": dir,
    "vars": vars,
    "input": None,  # Explicitly blocked — agents should not prompt for input
    # Exceptions (so the code can use try/except)
    "Exception": Exception,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
    "AttributeError": AttributeError,
    "RuntimeError": RuntimeError,
    "StopIteration": StopIteration,
    "ZeroDivisionError": ZeroDivisionError,
    "FileNotFoundError": FileNotFoundError,
    "NotImplementedError": NotImplementedError,
    # Booleans & None
    "True": True,
    "False": False,
    "None": None,
}


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
        try:
            return self._execute_pipeline(code)
        except SecurityBlockedError as exc:
            return str(exc)

    def _execute_pipeline(self, code: str) -> str:
        """Run validation layers then execute the code in a sandboxed env."""
        # ── Layer 1: AST Static Analysis ──────────────────────────────────
        ASTValidator(self.policy).validate(code)

        # ── Layer 2: Network Filter ────────────────────────────────────────
        NetworkFilter(self.policy).validate(code)

        # ── Layer 3: Semantic Judge (optional) ────────────────────────────
        if self.policy.use_semantic_judge and self.judge_llm is not None:
            SemanticJudge(self.judge_llm).validate(code)

        # ── All checks passed — execute safely with timeout ───────────────
        return self._safe_exec(code)

    def _safe_exec(self, code: str) -> str:
        """
        Execute code in a sandboxed environment with:
        - Restricted builtins (no exec/eval/open)
        - A controlled __import__ that only allows policy-whitelisted modules
        - stdout capture (print statements are returned)
        - Timeout enforcement (SecurityPolicy.execution_timeout)
        """
        local_vars: dict = {}
        stdout_capture = io.StringIO()
        exec_error: list[Exception] = []

        # Build builtins with a restricted __import__ for this execution
        sandboxed_builtins = {**_SAFE_BUILTINS}
        sandboxed_builtins["__import__"] = self._make_restricted_import()

        def _target() -> None:
            try:
                with redirect_stdout(stdout_capture):
                    exec(code, {"__builtins__": sandboxed_builtins}, local_vars)  # noqa: S102
            except Exception as exc:
                exec_error.append(exc)

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()
        thread.join(timeout=self.policy.execution_timeout)

        if thread.is_alive():
            return (
                f"[AgentGuard] TIMEOUT — Code execution exceeded "
                f"{self.policy.execution_timeout}s limit. "
                f"Rewrite the code to be faster or reduce the data size."
            )

        if exec_error:
            return f"Execution error: {exec_error[0]}"

        # Build output from stdout and/or the 'result' variable
        printed = stdout_capture.getvalue()
        result = local_vars.get("result", None)

        parts: list[str] = []
        if printed.strip():
            parts.append(printed.strip())
        if result is not None:
            parts.append(str(result))

        if parts:
            return "\n".join(parts)
        return "Code executed successfully (no output produced)."

    def _make_restricted_import(self):  # noqa: ANN202
        """
        Create a restricted __import__ that only allows policy-whitelisted modules.

        This is necessary because Python's `import X` statement internally calls
        `__import__('X', ...)`. Without this, any code using `import` inside
        the sandboxed exec() would fail — even for allowed modules like `math`.

        Safety note: by the time code reaches _safe_exec, it has already passed
        the AST validator which checks that only whitelisted modules are imported.
        This restricted __import__ is a defense-in-depth measure.
        """
        allowed = set(self.policy.allowed_modules)

        def _restricted_import(
            name: str,
            globals: dict = None,  # noqa: A002
            locals: dict = None,  # noqa: A002
            fromlist: tuple = (),
            level: int = 0,
        ):  # noqa: ANN202
            root_module = name.split(".")[0]
            if root_module not in allowed:
                raise ImportError(
                    f"Import of '{root_module}' is not allowed by the security policy."
                )
            return __builtins__["__import__"](name, globals, locals, fromlist, level)

        return _restricted_import

