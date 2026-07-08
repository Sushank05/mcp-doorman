/**
 * End-to-end: a real MCP client connects to a real gateway process, which
 * spawns the (deliberately misbehaving) demo server. Everything runs over
 * actual stdio transports — no mocks.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pinFile = path.join(repoRoot, "node_modules", ".cache", "doorman-e2e.pins.json");

function gatewayTransport(fixture: string) {
  return new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", "src/cli.ts", "run", "--config", `tests/fixtures/${fixture}`],
    cwd: repoRoot,
    env: Object.fromEntries(
      Object.entries(process.env).filter(([, v]) => v !== undefined),
    ) as Record<string, string>,
    stderr: "inherit",
  });
}

async function connect(fixture: string, options?: { autoApprove?: boolean; elicitation?: boolean }) {
  const client = new Client(
    { name: "doorman-e2e", version: "0.0.0" },
    options?.elicitation ? { capabilities: { elicitation: {} } } : { capabilities: {} },
  );
  if (options?.elicitation) {
    client.setRequestHandler(ElicitRequestSchema, async () => ({
      action: "accept" as const,
      content: { decision: options.autoApprove ? "approve" : "deny" },
    }));
  }
  await client.connect(gatewayTransport(fixture));
  return client;
}

function text(result: CallToolResult, index = 0): string {
  const item = result.content?.[index];
  return item && item.type === "text" ? item.text : "";
}

function allText(result: CallToolResult): string {
  return (result.content ?? [])
    .map((c) => (c.type === "text" ? c.text : ""))
    .join("\n");
}

describe("gateway e2e", () => {
  let client: Client;

  beforeAll(async () => {
    client = await connect("e2e.config.json");
  });

  afterAll(async () => {
    await client.close();
  });

  it("lists namespaced tools and hides policy-denied ones", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("demo__add");
    expect(names).toContain("demo__read_config");
    expect(names).not.toContain("demo__delete_everything"); // denied → hidden
    expect(names).toContain("doorman__status");
    expect(names).toContain("doorman__recent_events");
  });

  it("marks approval-gated tools in their description", async () => {
    const { tools } = await client.listTools();
    const sendEmail = tools.find((t) => t.name === "demo__send_email");
    expect(sendEmail?.description).toContain("requires interactive user approval");
  });

  it("proxies innocent calls untouched", async () => {
    const result = (await client.callTool({
      name: "demo__add",
      arguments: { a: 2, b: 3 },
    })) as CallToolResult;
    expect(result.isError).toBeFalsy();
    expect(text(result)).toBe("5");
  });

  it("redacts secrets from tool results", async () => {
    const result = (await client.callTool({
      name: "demo__read_config",
      arguments: {},
    })) as CallToolResult;
    const body = allText(result);
    expect(body).toContain("[REDACTED:aws-access-key-id]");
    expect(body).toContain("[REDACTED:github-token]");
    expect(body).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(body).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    expect(body).toContain("https://api.example.com"); // benign content survives
  });

  it("flags prompt-injection payloads with a warning banner", async () => {
    const result = (await client.callTool({
      name: "demo__fetch_webpage",
      arguments: {},
    })) as CallToolResult;
    expect(text(result, 0)).toContain("prompt-injection heuristics");
    expect(allText(result)).toContain("Totally normal product page"); // flagged, not withheld
  });

  it("blocks policy-denied tool calls", async () => {
    const result = (await client.callTool({
      name: "demo__delete_everything",
      arguments: {},
    })) as CallToolResult;
    expect(result.isError).toBe(true);
    expect(text(result)).toContain("denied by policy");
  });

  it("enforces per-tool rate limits", async () => {
    const one = (await client.callTool({
      name: "demo__echo",
      arguments: { text: "1" },
    })) as CallToolResult;
    const two = (await client.callTool({
      name: "demo__echo",
      arguments: { text: "2" },
    })) as CallToolResult;
    const three = (await client.callTool({
      name: "demo__echo",
      arguments: { text: "3" },
    })) as CallToolResult;
    expect(one.isError).toBeFalsy();
    expect(two.isError).toBeFalsy();
    expect(three.isError).toBe(true);
    expect(text(three)).toContain("rate limit");
  });

  it("exposes gateway status as a built-in tool", async () => {
    const result = (await client.callTool({
      name: "doorman__status",
      arguments: {},
    })) as CallToolResult;
    const status = JSON.parse(text(result));
    expect(status.servers.demo.connected).toBe(true);
    expect(status.guards.injectionAction).toBe("flag");
  });
});

describe("approval gate", () => {
  it("denies approval-gated calls when the client has no elicitation support", async () => {
    const client = await connect("e2e.config.json");
    try {
      const result = (await client.callTool({
        name: "demo__send_email",
        arguments: { to: "a@b.co", subject: "hi", body: "hello" },
      })) as CallToolResult;
      expect(result.isError).toBe(true);
      expect(text(result)).toContain("did not approve");
    } finally {
      await client.close();
    }
  });

  it("allows the call when the user approves via elicitation", async () => {
    const client = await connect("e2e.config.json", { elicitation: true, autoApprove: true });
    try {
      const result = (await client.callTool({
        name: "demo__send_email",
        arguments: { to: "a@b.co", subject: "hi", body: "hello" },
      })) as CallToolResult;
      expect(result.isError).toBeFalsy();
      expect(text(result)).toContain("email sent");
    } finally {
      await client.close();
    }
  });

  it("blocks the call when the user denies via elicitation", async () => {
    const client = await connect("e2e.config.json", { elicitation: true, autoApprove: false });
    try {
      const result = (await client.callTool({
        name: "demo__send_email",
        arguments: { to: "a@b.co", subject: "hi", body: "hello" },
      })) as CallToolResult;
      expect(result.isError).toBe(true);
      expect(text(result)).toContain("did not approve");
    } finally {
      await client.close();
    }
  });
});

describe("tool pinning (TOFU)", () => {
  it("writes a pin file on first contact", async () => {
    rmSync(pinFile, { force: true });
    const client = await connect("pinning.config.json");
    try {
      await client.listTools();
      expect(existsSync(pinFile)).toBe(true);
    } finally {
      await client.close();
      rmSync(pinFile, { force: true });
    }
  });
});
