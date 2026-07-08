# Contributing to mcp-doorman

Thanks for helping make the MCP ecosystem safer. All contributions are welcome — detection rules, guards, docs, bug reports, threat research.

## Getting started

```bash
git clone https://github.com/Sushank05/mcp-doorman
cd mcp-doorman
npm install
npm test        # unit tests + a real stdio end-to-end suite
npm run demo    # see every guard fire against a misbehaving demo server
```

Requirements: Node.js ≥ 20. The codebase is TypeScript (strict), tested with vitest, no build step needed to run tests (`tsx` handles it).

## The easiest contribution: a detection rule

Redaction rules live in [src/redact.ts](src/redact.ts), injection patterns in [src/injection.ts](src/injection.ts). Adding one is a ~10-line PR:

1. Add the rule with a `name`, `description`, and a `g`-flagged regex.
2. Add tests in `tests/redact.test.ts` or `tests/injection.test.ts` — **both a true-positive and a false-positive case are required.**
3. If the rule is noisy for common legitimate content, mark it `optIn: true`.

See [docs/detection-rules.md](docs/detection-rules.md) for the full guidelines, and use the *"Detection rule proposal"* issue template if you want feedback before writing code.

## Project map


| Path                                                  | What lives there                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------- |
| `src/gateway.ts`                                      | The guard pipeline — where list/call interception happens        |
| `src/upstream.ts`                                     | MCP client connections to upstream servers                       |
| `src/redact.ts`, `src/injection.ts`                   | Detection rules (start here!)                                    |
| `src/policy.ts`, `src/ratelimit.ts`, `src/pinning.ts` | Individual guards                                                |
| `src/config.ts`                                       | Config schema (zod) and loading                                  |
| `src/audit.ts`                                        | JSONL audit log                                                  |
| `tests/gateway.e2e.test.ts`                           | Real client ↔ gateway ↔ server, no mocks                         |
| `examples/demo-server.mjs`                            | The deliberately misbehaving upstream used by tests and the demo |




## Pull request checklist

- `npm run build && npm test` passes locally (CI runs Linux + Windows, Node 20/22/24).
- New behavior has tests. Detection rules have true-positive *and* false-positive tests.
- User-facing changes are reflected in README.md.
- Keep PRs focused — one guard/rule/fix per PR reviews much faster.



## Reporting security issues

**Do not open a public issue for vulnerabilities in mcp-doorman itself.** See [SECURITY.md](SECURITY.md).

New *attack techniques* the guards should catch (novel injection phrasings, bypasses of existing rules) are welcome as regular issues — that's threat research, and it makes the rules better for everyone.

## Code style

- TypeScript strict; small focused modules; every module has a header comment saying *why* it exists.
- Logs go to **stderr** — stdout carries the MCP protocol. Never `console.log` in gateway code paths.
- Fail safe: when a guard errors, prefer blocking over silently allowing.

