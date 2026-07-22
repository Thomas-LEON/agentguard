"""LangChain integration for secure external Python execution."""

import warnings
from typing import Any

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from agentguard.exceptions import SecurityBlockedError
from agentguard.judges.gemini_judge import SemanticJudge
from agentguard.policy import SecurityPolicy
from agentguard.sandbox import (
    DockerSandboxExecutor,
    SandboxExecutor,
    SandboxUnavailableError,
)
from agentguard.validators.ast_validator import ASTValidator
from agentguard.validators.network_filter import NetworkFilter


class _CodeInput(BaseModel):
    """Input schema for the SafePythonREPLTool."""

    code: str = Field(description="The Python code to execute.")


class SafePythonREPLTool(BaseTool):
    """A LangChain tool that validates code then runs it outside this process.

    The default executor is DockerSandboxExecutor. It fails closed if Docker is
    unavailable rather than falling back to an in-process Python exec call.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = "safe_python_repl"
    description: str = (
        "A Python interpreter isolated by an external sandbox. Use it to execute "
        "code. Unsafe operations may be blocked by the policy before execution."
    )
    args_schema: type[BaseModel] = _CodeInput
    policy: SecurityPolicy = Field(default_factory=SecurityPolicy)
    judge_llm: BaseChatModel | None = None
    sandbox: Any = Field(default_factory=DockerSandboxExecutor)

    def model_post_init(self, __context: object) -> None:
        """Warn if semantic review is requested without an LLM."""
        if self.policy.use_semantic_judge and self.judge_llm is None:
            warnings.warn(
                "[AgentGuard] use_semantic_judge=True but no judge_llm was provided. "
                "Layer 3 (Semantic Judge) will be skipped. Pass a judge_llm to "
                "enable it, or set use_semantic_judge=False to suppress this warning.",
                UserWarning,
                stacklevel=2,
            )

    def _run(
        self,
        code: str,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        """Run policy checks and return execution feedback to the agent."""
        try:
            return self._execute_pipeline(code)
        except SecurityBlockedError as exc:
            return str(exc)
        except SandboxUnavailableError as exc:
            return f"[AgentGuard] SANDBOX UNAVAILABLE - {exc}"

    def _execute_pipeline(self, code: str) -> str:
        """Run validation layers before external execution."""
        ASTValidator(self.policy).validate(code)
        NetworkFilter(self.policy).validate(code)

        if self.policy.use_semantic_judge and self.judge_llm is not None:
            SemanticJudge(self.judge_llm).validate(code)

        return self._safe_exec(code)

    def _safe_exec(self, code: str) -> str:
        """Execute code only through the configured external sandbox."""
        executor: SandboxExecutor = self.sandbox
        return executor.execute(code, self.policy).output
