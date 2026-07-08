import { describe, expect, it } from "vitest";
import { evaluatePolicy, globToRegExp, matchesGlob, type PolicyRule } from "../src/policy.js";

describe("globToRegExp", () => {
  it("matches literals exactly", () => {
    expect(globToRegExp("github__create_issue").test("github__create_issue")).toBe(true);
    expect(globToRegExp("github__create_issue").test("github__create_issues")).toBe(false);
  });

  it("supports * wildcards", () => {
    expect(matchesGlob("files__delete_file", "*__delete*")).toBe(true);
    expect(matchesGlob("files__read_file", "*__delete*")).toBe(false);
    expect(matchesGlob("github__anything", "github__*")).toBe(true);
  });

  it("treats regex metacharacters literally", () => {
    expect(matchesGlob("a.b", "a.b")).toBe(true);
    expect(matchesGlob("axb", "a.b")).toBe(false);
  });
});

describe("evaluatePolicy", () => {
  const rules: PolicyRule[] = [
    { match: "files__delete*", action: "deny", reason: "no deletions" },
    { match: ["github__create_*", "github__update_*"], action: "approve" },
    { match: "files__*", action: "allow" },
  ];

  it("first matching rule wins", () => {
    expect(evaluatePolicy("files__delete_file", rules, "allow").action).toBe("deny");
    expect(evaluatePolicy("files__read_file", rules, "deny").action).toBe("allow");
  });

  it("supports array matches", () => {
    expect(evaluatePolicy("github__create_issue", rules, "allow").action).toBe("approve");
    expect(evaluatePolicy("github__update_issue", rules, "allow").action).toBe("approve");
  });

  it("falls back to the default action", () => {
    expect(evaluatePolicy("slack__post_message", rules, "deny").action).toBe("deny");
    expect(evaluatePolicy("slack__post_message", rules, "allow").action).toBe("allow");
  });

  it("carries the rule reason into the decision", () => {
    expect(evaluatePolicy("files__delete_file", rules, "allow").reason).toBe("no deletions");
    expect(evaluatePolicy("slack__post", rules, "deny").reason).toContain("default");
  });
});
