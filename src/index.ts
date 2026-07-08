/**
 * mcp-doorman — security gateway for Model Context Protocol servers.
 *
 * Library entry point: everything the CLI uses is exported here so the
 * gateway can be embedded in other Node processes or extended in tests.
 */

export { AuditLog, type AuditEvent } from "./audit.js";
export {
  ConfigSchema,
  loadConfig,
  parseConfig,
  interpolateEnv,
  RESERVED_SERVER_KEY,
  type DoormanConfig,
  type LoadedConfig,
  type ServerConfig,
} from "./config.js";
export { Gateway } from "./gateway.js";
export {
  INJECTION_PATTERNS,
  scanForInjection,
  type InjectionFinding,
  type InjectionPattern,
} from "./injection.js";
export { log, setLogLevel, type LogLevel } from "./logger.js";
export {
  applyPins,
  canonicalJson,
  diffAgainstPins,
  emptyPinFile,
  hashTool,
  loadPinFile,
  savePinFile,
  type PinFile,
  type PinnableTool,
  type PinnedTool,
  type ToolChange,
} from "./pinning.js";
export {
  evaluatePolicy,
  globToRegExp,
  matchesGlob,
  type PolicyAction,
  type PolicyDecision,
  type PolicyRule,
} from "./policy.js";
export { RateLimiter } from "./ratelimit.js";
export {
  BUILTIN_RULES,
  activeRules,
  luhnCheck,
  redactText,
  type RedactionHit,
  type RedactionResult,
  type RedactionRule,
} from "./redact.js";
export { Upstream } from "./upstream.js";
export { VERSION } from "./version.js";
