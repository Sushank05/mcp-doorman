# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-08

Initial release.

### Added
- Stdio gateway proxying multiple upstream MCP servers (stdio + streamable HTTP) behind one connection, with `server__tool` namespacing
- Policy engine: allow / deny / approve rules with glob matching, first-match-wins
- Secret redaction: 19 built-in rules (AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Google, npm, PEM keys, JWTs, bearer tokens, basic-auth URLs, generic credentials, Luhn-checked cards; opt-in email/SSN/IPv4) plus custom rules
- Prompt-injection screening of tool results **and tool descriptions** (tool-poisoning defense), flag or block modes, 9 built-in patterns plus custom
- Tool pinning (TOFU): SHA-256 hashes of the full tool surface, rug-pull blocking, `mcp-doorman pin` command
- Human approval gates via MCP elicitation, with configurable fallback for clients without elicitation support
- Per-tool token-bucket rate limiting
- Append-only JSONL audit log with pre-redacted arguments
- Built-in `doorman__status` and `doorman__recent_events` tools
- CLI: `run`, `pin`, `init`
- Demo server + `npm run demo` walkthrough
- 69 tests including a full stdio end-to-end suite
