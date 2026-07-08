import { describe, expect, it } from "vitest";
import { activeRules, luhnCheck, redactText, type RedactionRule } from "../src/redact.js";

const rules = activeRules();
const redact = (text: string) => redactText(text, rules);

describe("redactText", () => {
  it("leaves clean text untouched", () => {
    const text = "The build finished in 42 seconds with 0 errors.";
    const result = redact(text);
    expect(result.text).toBe(text);
    expect(result.hits).toEqual([]);
  });

  it("redacts AWS access key IDs", () => {
    const result = redact("key: AKIAIOSFODNN7EXAMPLE done");
    expect(result.text).toContain("[REDACTED:aws-access-key-id]");
    expect(result.text).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("redacts GitHub tokens", () => {
    const result = redact("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    expect(result.text).toContain("[REDACTED:github-token]");
  });

  it("redacts PEM private key blocks", () => {
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nmore\n-----END RSA PRIVATE KEY-----";
    const result = redact(`before\n${pem}\nafter`);
    expect(result.text).toContain("[REDACTED:private-key-block]");
    expect(result.text).not.toContain("MIIEowIBAAKCAQEA");
    expect(result.text).toContain("before");
    expect(result.text).toContain("after");
  });

  it("redacts JWTs", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const result = redact(`Authorization uses ${jwt} here`);
    expect(result.text).toContain("[REDACTED:jwt]");
  });

  it("redacts generic key=value credentials but not short values", () => {
    const hit = redact('api_key = "abcd1234efgh5678"');
    expect(hit.text).toContain("[REDACTED:generic-credential]");
    const miss = redact("password: short");
    expect(miss.hits).toEqual([]);
  });

  it("redacts Anthropic-style keys", () => {
    const result = redact("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx");
    expect(result.text).toContain("[REDACTED:anthropic-key]");
  });

  it("counts multiple hits per rule", () => {
    const result = redact("AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE");
    expect(result.hits).toEqual([{ rule: "aws-access-key-id", count: 2 }]);
  });
});

describe("credit card rule (Luhn-verified)", () => {
  it("redacts a valid test card number", () => {
    const result = redact("card: 4111 1111 1111 1111 exp 12/28");
    expect(result.text).toContain("[REDACTED:credit-card]");
  });

  it("ignores digit runs that fail Luhn", () => {
    const result = redact("order id 4111 1111 1111 1112");
    expect(result.text).toContain("4111 1111 1111 1112");
  });

  it("luhnCheck validates correctly", () => {
    expect(luhnCheck("4111111111111111")).toBe(true);
    expect(luhnCheck("4111111111111112")).toBe(false);
    expect(luhnCheck("123")).toBe(false);
  });
});

describe("opt-in and configuration", () => {
  it("does not redact emails by default", () => {
    const result = redact("contact admin@example.com for access");
    expect(result.text).toContain("admin@example.com");
  });

  it("redacts emails when opted in", () => {
    const optIn = activeRules({ enableOptIn: ["email"] });
    const result = redactText("contact admin@example.com for access", optIn);
    expect(result.text).toContain("[REDACTED:email]");
  });

  it("respects disabled rules", () => {
    const without = activeRules({ disable: ["aws-access-key-id"] });
    const result = redactText("AKIAIOSFODNN7EXAMPLE", without);
    expect(result.text).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("applies custom rules", () => {
    const custom: RedactionRule = {
      name: "acme-internal-id",
      description: "test",
      pattern: /ACME-[0-9]{6}/g,
    };
    const result = redactText("ticket ACME-123456", activeRules({ custom: [custom] }));
    expect(result.text).toContain("[REDACTED:acme-internal-id]");
  });
});
