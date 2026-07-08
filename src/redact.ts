/**
 * Secret and PII redaction.
 *
 * Tool results flow straight into the model's context window. Anything a
 * server leaks there (an API key in a config file, a token in an error
 * message) becomes exfiltratable by any later prompt injection. These rules
 * scrub known secret formats out of tool results before the model sees them.
 *
 * Contributing a rule? See docs/detection-rules.md — every rule needs a
 * matching test in tests/redact.test.ts with a true-positive AND a
 * false-positive case.
 */

export interface RedactionRule {
  name: string;
  description: string;
  /** Must be constructed with the `g` flag. */
  pattern: RegExp;
  /** Optional post-match check to cut false positives (e.g. Luhn for cards). */
  verify?: (match: string) => boolean;
  /** Opt-in rules are skipped unless listed in `redaction.enableOptIn`. */
  optIn?: boolean;
}

export interface RedactionHit {
  rule: string;
  count: number;
}

export interface RedactionResult {
  text: string;
  hits: RedactionHit[];
}

/** Luhn checksum — filters out most non-card digit runs. */
export function luhnCheck(raw: string): boolean {
  const digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export const BUILTIN_RULES: RedactionRule[] = [
  {
    name: "private-key-block",
    description: "PEM-encoded private key blocks (RSA, EC, OpenSSH, PKCS#8...)",
    pattern:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    name: "aws-access-key-id",
    description: "AWS access key IDs (AKIA... permanent, ASIA... temporary)",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    name: "github-token",
    description: "GitHub personal access / OAuth / app tokens (ghp_, gho_, ghu_, ghs_, ghr_)",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,251}\b/g,
  },
  {
    name: "github-fine-grained-pat",
    description: "GitHub fine-grained personal access tokens",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  {
    name: "gitlab-pat",
    description: "GitLab personal access tokens",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,64}\b/g,
  },
  {
    name: "slack-token",
    description: "Slack bot/user/app tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,250}\b/g,
  },
  {
    name: "stripe-key",
    description: "Stripe secret and restricted keys",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,247}\b/g,
  },
  {
    name: "openai-key",
    description: "OpenAI API keys (contain the T3BlbkFJ marker)",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}\b/g,
  },
  {
    name: "anthropic-key",
    description: "Anthropic API keys",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/g,
  },
  {
    name: "google-api-key",
    description: "Google Cloud API keys",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    name: "npm-token",
    description: "npm access tokens",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    name: "jwt",
    description: "JSON Web Tokens (three base64url segments starting with eyJ)",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    name: "bearer-header",
    description: "Bearer tokens in Authorization-header style strings",
    pattern: /\b[Bb]earer\s+[A-Za-z0-9._~+/=-]{20,}/g,
  },
  {
    name: "basic-auth-url",
    description: "user:password@ credentials embedded in URLs",
    pattern: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@/g,
  },
  {
    name: "generic-credential",
    description:
      "key=value style assignments where the key looks like a secret (api_key, token, password...)",
    pattern:
      /(?<![A-Za-z0-9])(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-./+]{12,}["']?/gi,
  },
  {
    name: "credit-card",
    description: "Payment card numbers (13-19 digits, Luhn-validated, common IIN prefixes)",
    pattern: /\b[3-6](?:\d[ -]?){11,17}\d\b/g,
    verify: luhnCheck,
  },
  {
    name: "email",
    description: "Email addresses (PII — opt-in)",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    optIn: true,
  },
  {
    name: "us-ssn",
    description: "US Social Security numbers in dashed form (PII — opt-in)",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    optIn: true,
  },
  {
    name: "ipv4",
    description: "IPv4 addresses (opt-in — noisy for infrastructure tooling)",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    optIn: true,
  },
];

export interface RedactOptions {
  /** Rule names to disable. */
  disable?: string[];
  /** Opt-in rule names to enable (e.g. "email", "us-ssn", "ipv4"). */
  enableOptIn?: string[];
  /** Extra rules to apply after the built-ins. */
  custom?: RedactionRule[];
}

export function activeRules(options: RedactOptions = {}): RedactionRule[] {
  const disabled = new Set(options.disable ?? []);
  const optedIn = new Set(options.enableOptIn ?? []);
  const rules = BUILTIN_RULES.filter(
    (r) => !disabled.has(r.name) && (!r.optIn || optedIn.has(r.name)),
  );
  return rules.concat(options.custom ?? []);
}

export function redactText(text: string, rules: RedactionRule[]): RedactionResult {
  const hits: RedactionHit[] = [];
  let out = text;
  for (const rule of rules) {
    let count = 0;
    out = out.replace(rule.pattern, (match) => {
      if (rule.verify && !rule.verify(match)) return match;
      count++;
      return `[REDACTED:${rule.name}]`;
    });
    if (count > 0) hits.push({ rule: rule.name, count });
  }
  return { text: out, hits };
}
