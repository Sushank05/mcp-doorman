# Writing detection rules

Detection rules are the community heart of mcp-doorman. There are two kinds:

| Kind | File | Fires on |
|---|---|---|
| **Redaction rules** | [`src/redact.ts`](../src/redact.ts) | Secrets/PII in tool results (and optionally arguments) |
| **Injection patterns** | [`src/injection.ts`](../src/injection.ts) | Instruction-shaped content in tool results and tool descriptions |

## Ground rules

1. **Every rule ships with two tests minimum:** one true positive (the thing it must catch) and one false positive (a nearby legitimate string it must NOT catch). Put them in `tests/redact.test.ts` / `tests/injection.test.ts`.
2. **Regexes must use the `g` flag** (the engine relies on it) and should be anchored with `\b` or structure wherever possible.
3. **Bound your quantifiers.** Use `{0,40}` style gaps, never bare `.*` — unbounded gaps cause catastrophic false positives and can be slow on megabyte results.
4. **Prefer format markers over entropy.** `AKIA[0-9A-Z]{16}` is reliable; "32 hex chars" matches every git SHA. If the format alone is ambiguous, add a `verify` function (see the Luhn check on `credit-card`).
5. **Noisy rules are opt-in.** If a rule would fire on common legitimate output (emails, IPs, phone numbers), set `optIn: true` so users enable it deliberately.
6. **Name rules like slugs** (`aws-access-key-id`), describe them in one sentence. The name appears in `[REDACTED:<name>]` masks and audit events, so make it self-explanatory.

## Redaction rule anatomy

```ts
{
  name: "sendgrid-key",
  description: "SendGrid API keys",
  pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
},
```

With a verifier for ambiguous formats:

```ts
{
  name: "credit-card",
  description: "Payment card numbers (Luhn-validated)",
  pattern: /\b[3-6](?:\d[ -]?){11,17}\d\b/g,
  verify: luhnCheck,   // post-match check to kill false positives
},
```

## Injection pattern anatomy

```ts
{
  name: "instruction-override",
  description: 'Attempts to void prior instructions ("ignore all previous instructions")',
  pattern: /\b(?:ignore|disregard|forget|override)\b[\s\S]{0,40}?\b(?:previous|prior|...)\b/gi,
},
```

Injection patterns should describe an **attack shape**, not a single phrase. Think about paraphrases: "disregard the earlier rules" and "ignore all previous instructions" are the same attack. Bounded gaps (`[\s\S]{0,40}?`) between the anchor words absorb the variation.

### What makes a good injection pattern proposal

- A link or citation showing the technique in the wild (blog post, CVE, tweet, your own red-teaming) — or a demonstration against a real agent.
- Reasoning about false positives: what legitimate tool output could look like this? (Documentation about security is the classic trap — text *describing* injections shouldn't necessarily be blocked, which is why `flag` is the default action.)

## Testing your rule

```bash
npm test -- redact      # or: npm test -- injection
```

Users can also try rules without a code change via `redaction.custom` / `injection.custom` in their config — handy for validating an idea before opening a PR.
