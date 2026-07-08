#!/usr/bin/env node
/**
 * mcp-doorman CLI.
 *
 *   mcp-doorman run  --config doorman.config.json   start the gateway (default)
 *   mcp-doorman pin  --config doorman.config.json   trust the current tool definitions
 *   mcp-doorman init                                write a starter config
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { AuditLog } from "./audit.js";
import { loadConfig } from "./config.js";
import { Gateway } from "./gateway.js";
import { log, setLogLevel } from "./logger.js";
import { applyPins, diffAgainstPins, emptyPinFile, loadPinFile, savePinFile } from "./pinning.js";
import { Upstream } from "./upstream.js";
import { VERSION } from "./version.js";

const HELP = `mcp-doorman ${VERSION} — security gateway for MCP servers

Usage:
  mcp-doorman [run] --config <path>   Start the gateway over stdio (default command)
  mcp-doorman pin   --config <path>   Pin (trust) the current tool definitions of all upstreams
  mcp-doorman init  [--config <path>] Write a starter config file

Options:
  -c, --config <path>   Config file (default: ./doorman.config.json)
  -v, --version         Print version
  -h, --help            Show this help
`;

const STARTER_CONFIG = `{
  "servers": {
    "example": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"]
    }
  },
  "policy": {
    "defaultAction": "allow",
    "rules": [
      { "match": "*__delete*", "action": "deny", "reason": "destructive tools are denied by default" },
      { "match": ["*__create*", "*__send*"], "action": "approve", "reason": "writes require approval" }
    ]
  },
  "injection": { "action": "flag" },
  "pinning": { "enabled": true, "onChangedTool": "block" },
  "rateLimit": { "perMinute": 120 },
  "audit": { "enabled": true }
}
`;

interface ParsedArgs {
  command: "run" | "pin" | "init" | "help" | "version";
  configPath: string;
}

export function parseArgs(argv: string[]): ParsedArgs {
  let command: ParsedArgs["command"] = "run";
  let configPath = "doorman.config.json";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config" || a === "-c") {
      const next = argv[++i];
      if (!next) throw new Error("--config requires a path");
      configPath = next;
    } else if (a === "--version" || a === "-v") {
      command = "version";
    } else if (a === "--help" || a === "-h" || a === "help") {
      command = "help";
    } else if (a === "run" || a === "pin" || a === "init") {
      command = a;
    } else {
      throw new Error(`unknown argument "${a}" — try --help`);
    }
  }
  return { command, configPath };
}

async function runGateway(configPath: string): Promise<void> {
  const loaded = loadConfig(configPath);
  setLogLevel(loaded.config.logLevel);
  const audit = new AuditLog(loaded.auditFilePath);
  const gateway = new Gateway(loaded, audit);

  const shutdown = async (code: number) => {
    await gateway.shutdown();
    process.exit(code);
  };
  process.on("SIGINT", () => void shutdown(0));
  process.on("SIGTERM", () => void shutdown(0));
  // When the client goes away, stdin ends — exit instead of lingering.
  process.stdin.on("end", () => void shutdown(0));
  process.stdin.on("close", () => void shutdown(0));

  await gateway.start(new StdioServerTransport());
}

async function pinTools(configPath: string): Promise<void> {
  const loaded = loadConfig(configPath);
  setLogLevel(loaded.config.logLevel);
  if (!loaded.pinFilePath) {
    throw new Error("pinning is disabled in this config — enable pinning.enabled first");
  }
  const pins = loadPinFile(loaded.pinFilePath) ?? emptyPinFile();
  let total = 0;
  for (const [key, serverCfg] of Object.entries(loaded.config.servers)) {
    const upstream = new Upstream(key, serverCfg);
    await upstream.connect();
    const changes = diffAgainstPins(key, upstream.tools, pins);
    applyPins(pins, changes);
    for (const change of changes) {
      console.log(
        `  ${change.kind === "new" ? "pinned" : "RE-PINNED (definition had changed)"}: ${key}__${change.tool}`,
      );
    }
    total += changes.length;
    console.log(`${key}: ${upstream.tools.length} tools, ${changes.length} pin(s) updated`);
    await upstream.close();
  }
  savePinFile(loaded.pinFilePath, pins);
  console.log(`\nPin file written: ${loaded.pinFilePath} (${total} update(s))`);
}

function init(configPath: string): void {
  const target = resolve(configPath);
  if (existsSync(target)) {
    throw new Error(`${target} already exists — refusing to overwrite`);
  }
  writeFileSync(target, STARTER_CONFIG, "utf8");
  console.log(`Wrote starter config: ${target}

Next steps:
  1. Edit the config: replace the example server with your real MCP servers.
  2. Pin the current tool definitions:   mcp-doorman pin --config ${configPath}
  3. Point your MCP client at the gateway instead of the servers directly.

Claude Desktop / Claude Code / Cursor snippet:
  {
    "mcpServers": {
      "doorman": {
        "command": "npx",
        "args": ["-y", "mcp-doorman", "run", "--config", "${target.replace(/\\/g, "/")}"]
      }
    }
  }
`);
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  switch (parsed.command) {
    case "version":
      console.log(VERSION);
      return;
    case "help":
      console.log(HELP);
      return;
    case "init":
      init(parsed.configPath);
      return;
    case "pin":
      await pinTools(parsed.configPath);
      return;
    case "run":
      await runGateway(parsed.configPath);
      return;
  }
}

main().catch((err: unknown) => {
  log.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
