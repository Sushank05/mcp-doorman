# Security Policy

## Reporting a vulnerability

If you find a vulnerability in mcp-doorman itself (a guard bypass caused by a bug, a way to make the gateway leak what it should redact, command injection via config, etc.):

- **Please do not open a public issue.**
- Use GitHub's [private vulnerability reporting](../../security/advisories/new) on this repository.
- You can expect an acknowledgment within a few days. Please include a minimal reproduction.

## Scope notes

- **Heuristic evasion is not a vulnerability by itself.** The injection/redaction rules are documented as best-effort ([README → Honest limitations](README.md#honest-limitations)). Novel evasion techniques are *very welcome* as public issues or PRs adding rules — that is community threat research, not a security report.
- A bypass of a **hard guarantee** (policy `deny` rules, pinning `block` mode, the approval gate) *is* a vulnerability. Report it privately.

## Supported versions

Only the latest released version receives security fixes.
