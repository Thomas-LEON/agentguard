# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-21

### Added

- **SecurityPolicy** (Pydantic model): configurable allowed modules, domains, timeout, and semantic judge toggle.
- **Layer 1 — AST Static Validator**: blocks forbidden imports (`os`, `subprocess`, etc.) and dangerous built-in calls (`exec`, `eval`, `compile`, `open`, `getattr`, `setattr`, `delattr`, `globals`, `locals`).
- **Layer 2 — Network Filter**: detects and blocks network calls via `requests`, `httpx`, `aiohttp`, `urllib`, and raw `socket` connections against a domain whitelist.
- **Layer 3 — Semantic Judge (Gemini)**: uses a Gemini LLM with a strict binary prompt (SAFE/UNSAFE) to detect subtle malicious intent that evades static analysis.
- **SafePythonREPLTool**: LangChain `BaseTool` integration — drop-in replacement for `PythonREPLTool` with the full 3-layer pipeline.
  - Sandboxed `exec()` with safe builtins whitelist
  - `stdout` capture (print output returned to agent)
  - Execution timeout enforcement
  - `SecurityBlockedError` caught and returned as tool output for agent self-correction
- **SecurityBlockedError**: descriptive exception with layer name, reason, and blocked code — designed for agent feedback loops.
- Full **pytest** test suite with mocked LLM for the semantic judge.
- **GitHub Actions CI**: automated testing on Python 3.11/3.12 with Ruff linting.
- **Examples**: `basic_agent.py` and `threat_intel_demo.py`.
- Project scaffolding: `pyproject.toml` (Poetry), `.pre-commit-config.yaml`, `CONTRIBUTING.md`, `SECURITY.md`.
