/**
 * Tool-call policy engine.
 *
 * Rules are evaluated top to bottom against the namespaced tool name
 * (`<server>__<tool>`); the first match wins. If nothing matches, the
 * configured default action applies.
 *
 * Actions:
 *  - "allow"   — pass the call through
 *  - "deny"    — block the call AND hide the tool from tools/list
 *  - "approve" — require interactive user approval (via MCP elicitation)
 */

export type PolicyAction = "allow" | "deny" | "approve";

export interface PolicyRule {
  /** Glob pattern(s); `*` matches any run of characters. */
  match: string | string[];
  action: PolicyAction;
  reason?: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  rule?: PolicyRule;
  reason: string;
}

/** Convert a `*`-glob into an anchored RegExp. Everything else is literal. */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\?]/g, "\\$&").replace(/\*/g, "[\\s\\S]*");
  return new RegExp(`^${escaped}$`);
}

export function matchesGlob(name: string, glob: string | string[]): boolean {
  const patterns = Array.isArray(glob) ? glob : [glob];
  return patterns.some((p) => globToRegExp(p).test(name));
}

export function evaluatePolicy(
  toolName: string,
  rules: PolicyRule[],
  defaultAction: PolicyAction,
): PolicyDecision {
  for (const rule of rules) {
    if (matchesGlob(toolName, rule.match)) {
      const patterns = Array.isArray(rule.match) ? rule.match.join(", ") : rule.match;
      return {
        action: rule.action,
        rule,
        reason: rule.reason ?? `matched policy rule "${patterns}"`,
      };
    }
  }
  return { action: defaultAction, reason: `policy default (${defaultAction})` };
}
