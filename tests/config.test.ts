import { describe, expect, it } from "vitest";
import { interpolateEnv, parseConfig } from "../src/config.js";

const minimal = { servers: { demo: { command: "node", args: ["server.js"] } } };

describe("parseConfig", () => {
  it("applies defaults to a minimal config", () => {
    const { config } = parseConfig(minimal, "/tmp/doorman.config.json", {});
    expect(config.policy.defaultAction).toBe("allow");
    expect(config.redaction.enabled).toBe(true);
    expect(config.injection.action).toBe("flag");
    expect(config.pinning.enabled).toBe(true);
    expect(config.rateLimit.perMinute).toBe(120);
    expect(config.approval.fallback).toBe("deny");
    expect(config.logLevel).toBe("info");
  });

  it("derives pin and audit file paths from the config path", () => {
    const loaded = parseConfig(minimal, "/tmp/doorman.config.json", {});
    expect(loaded.pinFilePath?.replace(/\\/g, "/")).toContain("doorman.config.pins.json");
    expect(loaded.auditFilePath?.replace(/\\/g, "/")).toContain("doorman.config.audit.jsonl");
  });

  it("rejects an empty servers map", () => {
    expect(() => parseConfig({ servers: {} }, "x.json", {})).toThrow(/no servers/);
  });

  it("rejects the reserved server key", () => {
    expect(() =>
      parseConfig({ servers: { doorman: { command: "node" } } }, "x.json", {}),
    ).toThrow(/reserved/);
  });

  it("rejects keys containing the namespace separator", () => {
    expect(() =>
      parseConfig({ servers: { bad__key: { command: "node" } } }, "x.json", {}),
    ).toThrow(/invalid server key/);
  });

  it("requires exactly one of command or url", () => {
    expect(() => parseConfig({ servers: { s: {} } }, "x.json", {})).toThrow(/exactly one/);
    expect(() =>
      parseConfig(
        { servers: { s: { command: "node", url: "http://localhost:3000/mcp" } } },
        "x.json",
        {},
      ),
    ).toThrow(/exactly one/);
  });

  it("rejects invalid urls", () => {
    expect(() => parseConfig({ servers: { s: { url: "not a url" } } }, "x.json", {})).toThrow(
      /invalid url/,
    );
  });

  it("interpolates environment variables into env, args and headers", () => {
    const raw = {
      servers: {
        s: {
          command: "node",
          args: ["--token", "${MY_TOKEN}"],
          env: { API_KEY: "${MY_TOKEN}" },
        },
      },
    };
    const { config } = parseConfig(raw, "x.json", { MY_TOKEN: "abc123" });
    expect(config.servers.s.args).toEqual(["--token", "abc123"]);
    expect(config.servers.s.env.API_KEY).toBe("abc123");
  });

  it("throws a helpful error for unset environment variables", () => {
    const raw = { servers: { s: { command: "node", env: { K: "${NOPE_NOT_SET}" } } } };
    expect(() => parseConfig(raw, "x.json", {})).toThrow(/NOPE_NOT_SET/);
  });

  it("disables pin/audit paths when those guards are off", () => {
    const raw = {
      ...minimal,
      pinning: { enabled: false },
      audit: { enabled: false },
    };
    const loaded = parseConfig(raw, "x.json", {});
    expect(loaded.pinFilePath).toBeNull();
    expect(loaded.auditFilePath).toBeNull();
  });
});

describe("interpolateEnv", () => {
  it("replaces ${VAR} placeholders", () => {
    expect(interpolateEnv("a-${X}-b", { X: "1" })).toBe("a-1-b");
  });

  it("leaves plain strings alone", () => {
    expect(interpolateEnv("no placeholders", {})).toBe("no placeholders");
  });
});
