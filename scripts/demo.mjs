#!/usr/bin/env node
/**
 * Live demo: spins up the gateway in front of the deliberately misbehaving
 * demo server and shows each guard firing. Run with: npm run demo
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

const client = new Client({ name: "doorman-demo", version: "0.0.0" }, { capabilities: {} });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", "src/cli.ts", "run", "--config", "examples/doorman.config.json"],
    cwd: repoRoot,
    env: Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== undefined)),
    stderr: "inherit",
  }),
);

const call = async (name, args = {}) => client.callTool({ name, arguments: args });
const firstText = (r) => r.content?.find((c) => c.type === "text")?.text ?? "";

console.log(bold("\n=== mcp-doorman demo — every guard, live ===\n"));

const { tools } = await client.listTools();
console.log(bold("1. tools/list through the gateway"));
console.log(`   exposed: ${tools.map((t) => t.name).join(", ")}`);
console.log(green("   ✔ demo__delete_everything is hidden (policy: deny)\n"));

console.log(bold("2. Innocent call passes through"));
console.log(`   demo__add(2, 3) → ${green(firstText(await call("demo__add", { a: 2, b: 3 })))}\n`);

console.log(bold("3. Secret redaction — demo__read_config leaks credentials"));
console.log(
  firstText(await call("demo__read_config"))
    .split("\n")
    .map((l) => `   ${l.includes("[REDACTED") ? green(l) : dim(l)}`)
    .join("\n"),
  "\n",
);

console.log(bold("4. Prompt-injection screening — demo__fetch_webpage carries a payload"));
const page = await call("demo__fetch_webpage");
console.log(`   ${green(firstText(page).split("\n")[0])}`);
console.log(dim("   (original page content still delivered below the warning)\n"));

console.log(bold("5. Policy denial — demo__delete_everything"));
console.log(`   ${red(firstText(await call("demo__delete_everything")))}\n`);

console.log(bold("6. Rate limiting — demo__echo is capped at 3/minute"));
for (let i = 1; i <= 4; i++) {
  const r = await call("demo__echo", { text: `call ${i}` });
  console.log(`   call ${i}: ${r.isError ? red(firstText(r)) : green("ok")}`);
}

console.log(bold("\n7. Gateway status (doorman__status)"));
const status = JSON.parse(firstText(await call("doorman__status")));
console.log(`   counters: ${JSON.stringify(status.counters)}\n`);

await client.close();
console.log(bold("Demo complete — see examples/doorman.config.json for the policy used.\n"));
process.exit(0);
