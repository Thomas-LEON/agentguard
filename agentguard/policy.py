"""
SecurityPolicy — Pydantic model defining the rules for AgentGuard.
"""

from pydantic import BaseModel, Field


class SecurityPolicy(BaseModel):
    """
    Defines the security rules applied by AgentGuard's pipeline.

    Attributes:
        allowed_modules: Python modules the agent is allowed to import.
            Defaults to a safe minimal set.
        allowed_domains: Hostnames/domains the agent is allowed to call.
            Use an empty list to block ALL network access.
        use_semantic_judge: Whether to enable the LLM-based semantic analysis
            (Layer 3). Requires a GEMINI_API_KEY. Disabling it speeds up
            execution but reduces detection of subtle malicious intent.
        execution_timeout: Maximum seconds allowed for code execution.

    Example:
        >>> policy = SecurityPolicy(
        ...     allowed_modules=["pandas", "json"],
        ...     allowed_domains=["api.github.com"],
        ...     use_semantic_judge=True,
        ... )
    """

    allowed_modules: list[str] = Field(
        default=["math", "json", "re", "datetime", "collections"],
        description="Whitelist of importable Python modules.",
    )
    allowed_attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Granular whitelist of specific allowed attributes/functions per module. "
        "If a module is present here, ONLY these attributes are allowed. "
        "Format: {'module_name': ['attr1', 'attr2']}",
    )
    denied_attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Granular blacklist of specific denied attributes/functions per module. "
        "Format: {'module_name': ['dangerous_attr']}",
    )
    allowed_domains: list[str] = Field(
        default=[],
        description="Whitelist of allowed network domains. Empty = no network.",
    )
    use_semantic_judge: bool = Field(
        default=True,
        description="Enable LLM-based semantic analysis (Layer 3).",
    )
    execution_timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Max seconds for code execution.",
    )
