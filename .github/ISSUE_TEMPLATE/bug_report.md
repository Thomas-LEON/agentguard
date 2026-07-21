---
name: 🐛 Bug Report
about: Report a bug or unexpected behavior in AgentGuard
title: "[BUG] "
labels: bug
assignees: ""
---

## Describe the Bug

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:

1. Configure policy with `...`
2. Run code `...`
3. See error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error messages and stack traces if available.

## Code to Reproduce

```python
from agentguard import SafePythonREPLTool, SecurityPolicy

policy = SecurityPolicy(...)
tool = SafePythonREPLTool(policy=policy)
result = tool._run("...")
```

## Environment

- **Python version**: [e.g. 3.11.9]
- **AgentGuard version**: [e.g. 0.1.0]
- **LangChain version**: [e.g. 0.2.x]
- **OS**: [e.g. Ubuntu 22.04]

## Additional Context

Add any other context about the problem here.
