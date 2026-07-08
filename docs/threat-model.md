# Threat model

## Setting

A developer runs an MCP client (Claude Desktop, Claude Code, Cursor, a custom agent) connected to one or more MCP servers. Servers are typically third-party code installed with `npx`/`uvx`, running with the developer's full user privileges, holding real credentials in their environment. The model's context window is the shared blast zone: whatever any tool returns becomes model input.

**Trust assumptions:** the client and model are trusted; the gateway (this project) is trusted; upstream servers and everything they touch (web pages, files, tickets, emails, API responses) are *untrusted*.

## Attacks and mitigations

| # | Attack | Vector | mcp-doorman mitigation | Strength |
|---|--------|--------|------------------------|----------|
| 1 | Tool poisoning | Malicious instructions in tool descriptions/schemas, hidden from client UI | Description scan on `tools/list` (`injection.scanToolDescriptions`), block or flag | Heuristic |
| 2 | Rug pull | Tool definition silently changes after user approval | SHA-256 pinning of the full tool surface; changed tools blocked until re-pinned | **Hard** (detects any byte change) |
| 3 | Indirect prompt injection | Instructions inside content fetched by legitimate tools | Result screening (flag banner or block) | Heuristic |
| 4 | Secret exfiltration | Credentials leak into context via one tool, exfiltrated via another | Result redaction (format-based rules) + injection screening of the "send it to..." instruction | Heuristic, layered |
| 5 | Over-privileged tools | A server exposes destructive tools the user never wanted the model to have | Policy `deny` (tool hidden AND calls blocked), `approve` (human gate) | **Hard** |
| 6 | Runaway agent loops | Hijacked/confused agent hammers a tool | Per-tool token-bucket rate limits | **Hard** |
| 7 | Consequential actions without consent | Model sends email / spends money / deletes prod | `approve` policy → interactive elicitation prompt; deny-by-default fallback | **Hard** (when client supports elicitation) |
| 8 | Unicode smuggling | Zero-width/tag characters hide instructions from human review | `invisible-unicode` pattern | Heuristic |

"**Hard**" = enforced structurally; bypassing it requires a bug in the gateway (report those privately — see [SECURITY.md](../SECURITY.md)). "Heuristic" = best-effort screening that raises the bar and the noise floor for attackers; bypasses are expected and are welcome public contributions as new rules.

## Explicit non-goals

- **Process sandboxing.** Upstream servers still run with your privileges. A malicious server can ignore MCP entirely and just read your disk. Doorman constrains the *protocol channel*; use containers/VMs to constrain the process. The two compose well.
- **Network egress control.** A server can phone home directly. Same answer: run it in a sandbox with egress rules.
- **Model alignment.** If the model itself decides to misbehave within its allowed tools, policy and approval gates are the only backstop here.
- **Multi-tenant auth.** This is a single-user, client-side gateway. Enterprise gateways (auth, quotas, fleets) are a different product category.

## Failure posture

Guards fail closed where feasible: unparseable config refuses to start; a pin-file mismatch blocks the tool; an elicitation failure applies the (default-deny) fallback. The exception is redaction/injection scanning of *content*, which fails open by design — blocking every result whenever a regex engine hiccups would make the gateway unusable, and content screening is documented as best-effort.
