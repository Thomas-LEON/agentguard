# 🛡️ AgentGuard

> **A security middleware for LangChain agents** — intercept, validate and safely execute LLM-generated code.

[![CI](https://github.com/thomasleon/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasleon/agentguard/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-red.svg)](https://github.com/astral-sh/ruff)

---

## 🤔 The Problem

Modern LangChain agents are powerful because they can **generate and execute Python code** autonomously. But this power is a double-edged sword.

A single malicious prompt — or a hallucination — can lead an agent to generate code like this:

```python
# An agent asked to "clean up temp files" might generate:
import os
import shutil
shutil.rmtree("/var/data/users")  # 💀 Oops.
```

There is no native guardrail in LangChain to prevent this.

**AgentGuard is that guardrail.**

---

## ✅ The Solution

AgentGuard wraps your agent's code execution tool in a **3-layer security pipeline**. Before any LLM-generated code runs, it must pass through:

```
LLM Agent
    │
    ▼
┌─────────────────────────────────────┐
│  Layer 1 │ AST Static Validator     │  Blocks forbidden imports & syscalls
│  Layer 2 │ Network Filter           │  Blocks calls to non-whitelisted domains
│  Layer 3 │ Gemini Semantic Judge    │  Detects subtle malicious intent via LLM
└─────────────────────────────────────┘
    │
    ▼
 Safe exec()  →  Result back to Agent
```

If any layer blocks the code, the agent receives a **descriptive error** and **self-corrects** — no crash, no data loss.

---

## 🚀 Quick Start

```bash
pip install agentguard
```

```python
import os
from agentguard import SafePythonREPLTool, SecurityPolicy
from langchain_google_genai import ChatGoogleGenerativeAI

os.environ["GEMINI_API_KEY"] = "your-api-key"

# Define your security rules
policy = SecurityPolicy(
    allowed_modules=["pandas", "json", "math"],
    allowed_domains=["api.github.com"],
    use_semantic_judge=True,
)

# Create the secure tool
judge_llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
safe_repl = SafePythonREPLTool(policy=policy, judge_llm=judge_llm)

# Use it in your LangChain agent instead of PythonREPLTool
# agent = create_react_agent(llm=your_llm, tools=[safe_repl])
```

---

## ⚙️ SecurityPolicy Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `allowed_modules` | `list[str]` | `["math", "json", ...]` | Whitelisted Python modules |
| `allowed_domains` | `list[str]` | `[]` (block all) | Whitelisted network domains |
| `use_semantic_judge` | `bool` | `True` | Enable Gemini LLM analysis |
| `execution_timeout` | `int` | `10` | Max execution seconds |

---

## 🔒 Security Layers in Detail

### Layer 1 — AST Static Validator
Uses Python's native `ast` module to parse the code **without executing it**. Blocks any import not on the whitelist and dangerous built-ins (`exec`, `eval`, `open`, `__import__`).

### Layer 2 — Network Filter
Uses regex to detect outbound HTTP calls (`requests.get`, `requests.post`, etc.) and validates the target domain against the whitelist. An empty whitelist blocks **all** network access.

### Layer 3 — Semantic Judge (Gemini)
For subtle attacks that evade static analysis (e.g. a loop that deletes files one-by-one), the code is sent to `gemini-1.5-flash` with a strict binary prompt. Only code classified as `SAFE` is allowed through.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

*Built by [Thomas LEON](https://linkedin.com/in/thomas-leon) · Emerging Technologies & AI Security*
