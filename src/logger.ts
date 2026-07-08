/**
 * Logging for the gateway process.
 *
 * IMPORTANT: when running over stdio, stdout carries the MCP protocol.
 * Every human-facing message MUST go to stderr.
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const ORDER: Record<Exclude<LogLevel, "silent">, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

let threshold = ORDER.info;

export function setLogLevel(level: LogLevel): void {
  threshold = level === "silent" ? Number.POSITIVE_INFINITY : ORDER[level];
}

export function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function emit(level: Exclude<LogLevel, "silent">, msg: string, extra?: unknown): void {
  if (ORDER[level] < threshold) return;
  const suffix = extra === undefined ? "" : ` ${safeJson(extra)}`;
  process.stderr.write(
    `[mcp-doorman] ${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${msg}${suffix}\n`,
  );
}

export const log = {
  debug: (msg: string, extra?: unknown) => emit("debug", msg, extra),
  info: (msg: string, extra?: unknown) => emit("info", msg, extra),
  warn: (msg: string, extra?: unknown) => emit("warn", msg, extra),
  error: (msg: string, extra?: unknown) => emit("error", msg, extra),
};
