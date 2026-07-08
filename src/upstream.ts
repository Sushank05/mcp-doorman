/**
 * Connection to one upstream MCP server (stdio child process or streamable
 * HTTP endpoint). The gateway is an MCP *client* toward upstreams and an MCP
 * *server* toward the real client (Claude Desktop, Cursor, an SDK agent...).
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  CallToolResultSchema,
  ToolListChangedNotificationSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { ServerConfig } from "./config.js";
import { log } from "./logger.js";
import { VERSION } from "./version.js";

export class Upstream {
  readonly client: Client;
  tools: Tool[] = [];
  connected = false;

  constructor(
    readonly key: string,
    private readonly cfg: ServerConfig,
  ) {
    this.client = new Client({ name: `mcp-doorman/${key}`, version: VERSION }, { capabilities: {} });
  }

  async connect(onToolsChanged?: (upstream: Upstream) => void): Promise<void> {
    const transport = this.cfg.url
      ? new StreamableHTTPClientTransport(
          new URL(this.cfg.url),
          Object.keys(this.cfg.headers).length > 0
            ? { requestInit: { headers: this.cfg.headers } }
            : undefined,
        )
      : new StdioClientTransport({
          command: this.cfg.command!,
          args: this.cfg.args,
          // getDefaultEnvironment() passes through only variables deemed safe
          // to inherit; everything else must be explicit in the config.
          env: { ...getDefaultEnvironment(), ...this.cfg.env },
          cwd: this.cfg.cwd,
          stderr: "inherit",
        });

    await this.client.connect(transport);
    this.connected = true;

    this.client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      log.info(`upstream "${this.key}" reported a tool list change`);
      try {
        await this.refreshTools();
      } catch (err) {
        log.warn(`failed to refresh tools for "${this.key}"`, { error: String(err) });
      }
      onToolsChanged?.(this);
    });

    await this.refreshTools();
    log.info(`connected to upstream "${this.key}" (${this.tools.length} tools)`);
  }

  async refreshTools(): Promise<void> {
    if (!this.client.getServerCapabilities()?.tools) {
      this.tools = [];
      return;
    }
    const tools: Tool[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.client.listTools(cursor ? { cursor } : {});
      tools.push(...page.tools);
      cursor = page.nextCursor;
    } while (cursor);
    this.tools = tools;
  }

  async callTool(
    name: string,
    args: Record<string, unknown> | undefined,
  ): Promise<CallToolResult> {
    return await this.client.request(
      { method: "tools/call", params: { name, arguments: args ?? {} } },
      CallToolResultSchema,
    );
  }

  async close(): Promise<void> {
    try {
      await this.client.close();
    } catch {
      // Already closing/closed — nothing useful to do.
    }
    this.connected = false;
  }
}
