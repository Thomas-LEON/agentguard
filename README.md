# AgentGuard

> Experimental guardrails and external execution for LangChain Python tools.

[![CI](https://github.com/Thomas-LEON/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Thomas-LEON/agentguard/actions)
[![PyPI](https://img.shields.io/pypi/v/securellm-agentguard.svg)](https://pypi.org/project/securellm-agentguard/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Status and threat model

AgentGuard is an alpha project. It helps LangChain applications apply a policy
before generated Python is executed, then executes approved code in an external
Docker container. It is not a substitute for a reviewed deployment architecture,
and its AST, regex and LLM checks are not security boundaries.

The Docker backend is the security boundary. It creates a short-lived container
with no host mounts, no network, a read-only root filesystem, a non-root user,
no Linux capabilities, and CPU, memory and PID limits. If Docker is unavailable,
execution fails closed: AgentGuard never falls back to Python exec in the host
process.

Docker and the configured container image are part of the trusted computing base.
Production users should pin a reviewed image digest and apply their own Docker
daemon policy. The default image contains only the Python standard library.

## Installation

Docker must be installed and available to the application process.

    pip install securellm-agentguard

For the optional Gemini semantic reviewer:

    pip install "securellm-agentguard[gemini]"

## Quick start

    from agentguard import SafePythonREPLTool, SecurityPolicy

    policy = SecurityPolicy(
        allowed_modules=["json", "math"],
        allowed_domains=[],
        use_semantic_judge=False,
        execution_timeout=10,
    )
    safe_repl = SafePythonREPLTool(policy=policy)

    # Pass safe_repl as a LangChain tool.

To use a reviewed image that includes additional packages, configure the
external executor explicitly:

    from agentguard import DockerSandboxExecutor, SafePythonREPLTool

    safe_repl = SafePythonREPLTool(
        policy=policy,
        sandbox=DockerSandboxExecutor(
            image="registry.example/agentguard-python@sha256:replace-with-digest"
        ),
    )

## Layers

1. AST pre-filter blocks disallowed imports and obvious dangerous calls.
2. Network pre-filter rejects known URL literals and calls outside the domain
   allowlist. Docker network isolation enforces the default no-network policy.
3. Optional semantic review asks a configured LLM for an advisory SAFE or UNSAFE
   verdict. It is fail-closed on unexpected answers, but must not be treated as
   an authorization boundary. Enabling it sends generated code to that provider.
4. Docker execution applies the operating-system-level containment controls.

## Security controls

SecurityPolicy configures the execution timeout plus memory_limit_mb, cpu_limit,
pids_limit, max_code_bytes and max_output_bytes. The executor terminates the
container on a timeout or output-limit violation; it does not leave a daemon
thread executing after returning a timeout message.

## Development

    poetry install
    poetry run pytest tests/ -v
    poetry run ruff check agentguard/ tests/
    poetry run mypy agentguard/

The default tests mock the external executor; Docker integration tests should run
separately in an environment where Docker is available.

## Responsible disclosure

Please report vulnerabilities according to [SECURITY.md](SECURITY.md). In
particular, do not publish sandbox-escape details before a coordinated fix.

## License

MIT - see [LICENSE](LICENSE).
