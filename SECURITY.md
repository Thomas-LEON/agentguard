# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Yes             |

## Reporting a Vulnerability

AgentGuard is a security tool — we take vulnerabilities in our own code **extremely seriously**.

If you discover a security vulnerability, please **do NOT** open a public GitHub issue.

### Responsible Disclosure

1. **Email**: Send a detailed report to `Thomas.leon1707@gmail.com`
2. **Subject line**: `[AgentGuard Security] <brief description>`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if you have one)

### Response Timeline

- **Acknowledgement**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix/Disclosure**: Within 30 days (coordinated with reporter)

### What Qualifies

- Bypasses of any of the 3 security layers (AST, Network, Semantic)
- Code that can escape the sandbox (`exec` with restricted builtins)
- Prompt injection attacks against the Semantic Judge
- Dependency vulnerabilities that affect AgentGuard's security guarantees

### Recognition

We will credit all responsible disclosures in our [CHANGELOG](CHANGELOG.md) and README (with your permission).

---

*Yes, we appreciate the irony of a security tool needing a security policy. That's precisely why we have one.* 🛡️
