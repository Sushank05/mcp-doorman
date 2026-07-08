/**
 * Configuration loading and validation.
 *
 * The config file is plain JSON. String values inside server `env`, `args`
 * and `headers` support `${VAR_NAME}` interpolation from the gateway's own
 * environment, so secrets never need to live in the config file itself.
 */

import { readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { z } from "zod";

export const RESERVED_SERVER_KEY = "doorman";
const SERVER_KEY_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

const ServerSchema = z.object({
  /** Executable to spawn for a stdio server (mutually exclusive with `url`). */
  command: z.string().optional(),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  cwd: z.string().optional(),
  /** Streamable HTTP endpoint (mutually exclusive with `command`). */
  url: z.string().optional(),
  headers: z.record(z.string(), z.string()).default({}),
});

const CustomPatternSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  pattern: z.string().min(1),
  flags: z.string().optional(),
});

const PolicyRuleSchema = z.object({
  match: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  action: z.enum(["allow", "deny", "approve"]),
  reason: z.string().optional(),
});

export const ConfigSchema = z.object({
  $schema: z.string().optional(),
  servers: z.record(z.string(), ServerSchema),
  policy: z
    .object({
      defaultAction: z.enum(["allow", "deny", "approve"]).default("allow"),
      rules: z.array(PolicyRuleSchema).default([]),
    })
    .prefault({}),
  redaction: z
    .object({
      enabled: z.boolean().default(true),
      /** Built-in rule names to disable. */
      disable: z.array(z.string()).default([]),
      /** Opt-in rule names to enable ("email", "us-ssn", "ipv4"). */
      enableOptIn: z.array(z.string()).default([]),
      custom: z.array(CustomPatternSchema).default([]),
      /** Also redact secrets found in model-supplied tool arguments. */
      redactArguments: z.boolean().default(false),
    })
    .prefault({}),
  injection: z
    .object({
      action: z.enum(["block", "flag", "off"]).default("flag"),
      scanToolDescriptions: z.boolean().default(true),
      custom: z.array(CustomPatternSchema).default([]),
    })
    .prefault({}),
  pinning: z
    .object({
      enabled: z.boolean().default(true),
      /** Defaults to `<config name>.pins.json` next to the config file. */
      pinFile: z.string().optional(),
      onNewTool: z.enum(["pin", "block"]).default("pin"),
      onChangedTool: z.enum(["block", "warn"]).default("block"),
    })
    .prefault({}),
  rateLimit: z
    .object({
      perMinute: z.number().default(120),
      /** Per-tool overrides, keyed by glob over the namespaced tool name. */
      perTool: z.record(z.string(), z.number()).default({}),
    })
    .prefault({}),
  approval: z
    .object({
      /** Applied when the client doesn't support elicitation (or it fails). */
      fallback: z.enum(["deny", "allow"]).default("deny"),
      timeoutMs: z.number().int().positive().default(120_000),
    })
    .prefault({}),
  audit: z
    .object({
      enabled: z.boolean().default(true),
      /** Defaults to `<config name>.audit.jsonl` next to the config file. */
      file: z.string().optional(),
      includeArguments: z.boolean().default(true),
      includeResults: z.boolean().default(false),
    })
    .prefault({}),
  gateway: z
    .object({
      exposeStatusTools: z.boolean().default(true),
      instructions: z.string().optional(),
    })
    .prefault({}),
  logLevel: z.enum(["debug", "info", "warn", "error", "silent"]).default("info"),
});

export type DoormanConfig = z.output<typeof ConfigSchema>;
export type ServerConfig = z.output<typeof ServerSchema>;

export interface LoadedConfig {
  config: DoormanConfig;
  configPath: string;
  configDir: string;
  /** Resolved pin file path, or null when pinning is disabled. */
  pinFilePath: string | null;
  /** Resolved audit file path, or null when audit logging is disabled. */
  auditFilePath: string | null;
}

export function interpolateEnv(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_all, name: string) => {
    const v = env[name];
    if (v === undefined) {
      throw new Error(
        `config references environment variable "${name}" which is not set — ` +
          `set it before starting mcp-doorman, or remove the \${${name}} placeholder`,
      );
    }
    return v;
  });
}

export function parseConfig(
  raw: unknown,
  configPath: string,
  env: NodeJS.ProcessEnv = process.env,
): LoadedConfig {
  let config: DoormanConfig;
  try {
    config = ConfigSchema.parse(raw);
  } catch (err) {
    if (err instanceof z.ZodError) {
      throw new Error(`invalid config at ${configPath}:\n${z.prettifyError(err)}`);
    }
    throw err;
  }

  const keys = Object.keys(config.servers);
  if (keys.length === 0) {
    throw new Error(`config at ${configPath} defines no servers — nothing to guard`);
  }
  for (const key of keys) {
    if (key === RESERVED_SERVER_KEY) {
      throw new Error(`server key "${RESERVED_SERVER_KEY}" is reserved for the gateway's own tools`);
    }
    if (!SERVER_KEY_RE.test(key) || key.includes("__")) {
      throw new Error(
        `invalid server key "${key}" — use letters, digits, "-" or single "_" ` +
          `(the "__" separator is reserved for tool namespacing)`,
      );
    }
    const server = config.servers[key];
    if (!server.command === !server.url) {
      throw new Error(
        `server "${key}" must set exactly one of "command" (stdio) or "url" (streamable HTTP)`,
      );
    }
    if (server.url) {
      try {
        new URL(server.url);
      } catch {
        throw new Error(`server "${key}" has an invalid url: ${server.url}`);
      }
    }
    server.args = server.args.map((a) => interpolateEnv(a, env));
    for (const map of [server.env, server.headers]) {
      for (const [k, v] of Object.entries(map)) map[k] = interpolateEnv(v, env);
    }
  }

  const configDir = dirname(configPath);
  const base = basename(configPath).replace(/\.json$/i, "");
  const pinFilePath = config.pinning.enabled
    ? resolve(configDir, config.pinning.pinFile ?? join(configDir, `${base}.pins.json`))
    : null;
  const auditFilePath = config.audit.enabled
    ? resolve(configDir, config.audit.file ?? join(configDir, `${base}.audit.jsonl`))
    : null;

  return { config, configPath, configDir, pinFilePath, auditFilePath };
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const abs = resolve(path);
  let text: string;
  try {
    text = readFileSync(abs, "utf8");
  } catch (err) {
    throw new Error(
      `cannot read config file ${abs}: ${(err as Error).message}\n` +
        `(run "mcp-doorman init" to create a starter config)`,
    );
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`config file ${abs} is not valid JSON: ${(err as Error).message}`);
  }
  return parseConfig(raw, abs, env);
}
