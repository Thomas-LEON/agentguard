"""
Custom exceptions for AgentGuard.
"""


class SecurityBlockedError(Exception):
    """
    Raised when AgentGuard blocks code execution due to a security violation.

    This exception is intentionally descriptive so that the LangChain agent
    can receive it as feedback and self-correct its next action.

    Example:
        >>> raise SecurityBlockedError(
        ...     layer="AST Validator",
        ...     reason="Forbidden import detected: 'os'",
        ...     code="import os; os.system('rm -rf /')"
        ... )
    """

    def __init__(self, layer: str, reason: str, code: str) -> None:
        self.layer = layer
        self.reason = reason
        self.code = code
        super().__init__(
            f"[AgentGuard | {layer}] BLOCKED — {reason}. "
            f"Rewrite the code without the forbidden operation."
        )
