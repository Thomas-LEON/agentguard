# Contributing to AgentGuard

First off — thank you for considering contributing to AgentGuard! 🛡️

## Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/agentguard.git
cd agentguard
```

### 2. Set Up Your Environment

We use [Poetry](https://python-poetry.org/) for dependency management:

```bash
pip install poetry
poetry install
```

### 3. Install Pre-Commit Hooks

```bash
pre-commit install
```

This ensures your code is automatically linted (Ruff) before each commit.

## Development Workflow

### Running Tests

```bash
poetry run pytest tests/ -v
```

Tests for Layer 3 (Semantic Judge) use mocks — no API key needed.

### Linting

```bash
poetry run ruff check agentguard/
poetry run ruff format agentguard/
```

### Type Checking

```bash
poetry run mypy agentguard/
```

## Pull Request Guidelines

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Write tests** for any new functionality. We aim for high coverage.

3. **Follow the commit convention**:
   - `feat:` — new feature
   - `fix:` — bug fix
   - `docs:` — documentation only
   - `test:` — adding or modifying tests
   - `chore:` — tooling, CI, dependencies

4. **Keep PRs focused** — one feature or fix per PR.

5. **Ensure CI passes** — all tests must pass and Ruff must not report errors.

## Code Style

- **Line length**: 88 characters (Ruff default)
- **Docstrings**: Google style
- **Type hints**: Required on all public APIs
- **Imports**: Sorted by Ruff (isort rules)

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) on GitHub.

## Suggesting Features

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) on GitHub.

## Security Vulnerabilities

Please **do NOT** open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

---

*Thank you for helping make AI agents safer!* 🙏
