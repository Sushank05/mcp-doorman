/**
 * Append-only JSONL audit log.
 *
 * Every security-relevant event (tool calls, denials, redactions, injection
 * flags, pin changes, approvals) is recorded with a timestamp. The file is
 * plain JSONL so it can be tailed, grepped, or shipped to any log pipeline.
 *
 * Arguments and results are redacted BEFORE they reach this module — the
 * audit log must never become the secret leak it exists to prevent.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { log } from "./logger.js";

export interface AuditEvent {
  ts: string;
  event: string;
  [key: string]: unknown;
}

export class AuditLog {
  private queue: Promise<unknown> = Promise.resolve();
  private recentBuffer: AuditEvent[] = [];
  readonly counters: Record<string, number> = {};

  constructor(
    private readonly file: string | null,
    private readonly maxRecent = 200,
  ) {
    if (file) {
      this.queue = mkdir(dirname(file), { recursive: true }).catch(() => undefined);
    }
  }

  record(event: string, fields: Record<string, unknown> = {}): AuditEvent {
    const evt: AuditEvent = { ts: new Date().toISOString(), event, ...fields };
    this.counters[event] = (this.counters[event] ?? 0) + 1;
    this.recentBuffer.push(evt);
    if (this.recentBuffer.length > this.maxRecent) this.recentBuffer.shift();
    if (this.file) {
      const file = this.file;
      // Serialized writes: appendFile calls must not interleave.
      this.queue = this.queue
        .then(() => appendFile(file, `${JSON.stringify(evt)}\n`, "utf8"))
        .catch((err) => log.warn("audit log write failed", { error: String(err) }));
    }
    return evt;
  }

  recent(limit = 20): AuditEvent[] {
    return this.recentBuffer.slice(-limit);
  }

  async flush(): Promise<void> {
    await this.queue.catch(() => undefined);
  }
}
