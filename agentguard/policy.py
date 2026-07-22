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
    memory_limit_mb: int = Field(
        default=128,
        ge=32,
        le=1024,
        description="Maximum memory available to the external sandbox.",
    )
    cpu_limit: float = Field(
        default=0.5,
        ge=0.1,
        le=4.0,
        description="Maximum CPU cores available to the external sandbox.",
    )
    pids_limit: int = Field(
        default=64,
        ge=16,
        le=512,
        description="Maximum processes and threads available to the sandbox.",
    )
    max_code_bytes: int = Field(
        default=65_536,
        ge=1_024,
        le=1_048_576,
        description="Maximum UTF-8 source size accepted for one execution.",
    )
    max_output_bytes: int = Field(
        default=65_536,
        ge=1_024,
        le=1_048_576,
        description="Maximum stdout and stderr captured from one execution.",
    )
