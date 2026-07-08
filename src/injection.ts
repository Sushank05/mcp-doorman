/**
 * Prompt-injection heuristics.
 *
 * Tool RESULTS are untrusted input: a compromised or malicious server (or a
 * webpage/file/ticket a legitimate server fetched) can embed instructions
 * aimed at the model. Tool DESCRIPTIONS are equally dangerous — that is the
 * "tool poisoning" attack class.
 *
 * These are heuristics, not proofs. A determined attacker can evade regexes;
 * the goal is to catch the common, documented attack shapes and to make the
 * model aware that a result is suspicious (flag mode) or keep it out of
 * context entirely (block mode). Defense in depth, not a force field.
 *
 * Contributing a pattern? See docs/detection-rules.md.
 */

export interface InjectionPattern {
  name: string;
  description: string;
  /** Must be constructed with the `g` flag. */
  pattern: RegExp;
}

export interface InjectionFinding {
  rule: string;
  /** Truncated, control-char-escaped excerpt of the matching text. */
  snippet: string;
}

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: "instruction-override",
    description: 'Attempts to void prior instructions ("ignore all previous instructions")',
    pattern:
      /\b(?:ignore|disregard|forget|override)\b[\s\S]{0,40}?\b(?:previous|prior|above|earlier|all|any|system)\b[\s\S]{0,40}?\b(?:instructions?|prompts?|rules?|messages?|context)\b/gi,
  },
  {
    name: "new-instructions",
    description: "Claims to supply replacement instructions or a new system prompt",
    pattern:
      /\b(?:new|updated|revised|real|actual|true)\s+(?:instructions?|system\s+prompt|rules?)\s*(?::|\bare\b|\bfollow\b)/gi,
  },
  {
    name: "concealment",
    description: "Tells the model to hide activity from the user",
    pattern:
      /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\b[\s\S]{0,30}?\b(?:the\s+)?(?:user|human|anyone|owner)\b/gi,
  },
  {
    name: "exfiltration-bait",
    description: "Instructs the model to send data to an external endpoint",
    pattern:
      /\b(?:send|post|upload|forward|exfiltrate|transmit)\b[\s\S]{0,60}?\b(?:to\s+)?(?:https?:\/\/|the\s+following\s+(?:url|address|endpoint)|webhook)/gi,
  },
  {
    name: "tool-coercion",
    description: "Urges the model to invoke a tool immediately or unconditionally",
    pattern:
      /\b(?:immediately|you\s+must(?:\s+first)?|before\s+(?:doing\s+)?anything\s+else)[\s,]{1,3}(?:run|call|invoke|execute|use)\b[\s\S]{0,60}?\btool\b/gi,
  },
  {
    name: "hidden-html-instructions",
    description: "HTML comments carrying instruction-like content",
    pattern:
      /<!--[\s\S]{0,400}?\b(?:instructions?|ignore|system\s+prompt|you\s+must|do\s+not\s+tell)\b[\s\S]{0,400}?-->/gi,
  },
  {
    name: "fake-conversation-tags",
    description: "Markup imitating chat-role or system-prompt delimiters",
    pattern: /<\/?(?:system|assistant|human)(?:_prompt|_message)?>|\[\/?(?:SYSTEM|INST)\]/g,
  },
  {
    name: "invisible-unicode",
    description:
      "Runs of zero-width/bidi control characters or Unicode tag characters (ASCII smuggling)",
    pattern:
      /[\u200B\u200C\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]{2,}|[\u{E0000}-\u{E007F}]/gu,
  },
  {
    name: "important-to-model",
    description: "Messages addressed directly at the AI assistant",
    pattern:
      /\b(?:IMPORTANT|ATTENTION|NOTE)\b[\s\S]{0,40}?\b(?:assistant|claude|gpt|gemini|copilot|the\s+model|ai\s+agent)\b/gi,
  },
];

function escapeControlChars(s: string): string {
  return s.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001F\u007F\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/**
 * Scan text for injection patterns. Returns at most one finding per rule
 * (the first match), with a short sanitized snippet for logs.
 */
export function scanForInjection(
  text: string,
  patterns: InjectionPattern[] = INJECTION_PATTERNS,
): InjectionFinding[] {
  const findings: InjectionFinding[] = [];
  for (const p of patterns) {
    // Never share exec state between scans.
    p.pattern.lastIndex = 0;
    const m = p.pattern.exec(text);
    if (m) {
      findings.push({
        rule: p.name,
        snippet: escapeControlChars(m[0].slice(0, 120)),
      });
    }
  }
  return findings;
}
