import { describe, expect, it } from "vitest";
import { RateLimiter } from "../src/ratelimit.js";

describe("RateLimiter", () => {
  it("allows bursts up to the per-minute capacity", () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    expect(limiter.take("tool", 2)).toBe(true);
    expect(limiter.take("tool", 2)).toBe(true);
    expect(limiter.take("tool", 2)).toBe(false);
  });

  it("refills continuously over time", () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    expect(limiter.take("tool", 2)).toBe(true);
    expect(limiter.take("tool", 2)).toBe(true);
    expect(limiter.take("tool", 2)).toBe(false);
    now = 30_000; // half a minute → one token refilled at 2/min
    expect(limiter.take("tool", 2)).toBe(true);
    expect(limiter.take("tool", 2)).toBe(false);
  });

  it("tracks buckets per key", () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    expect(limiter.take("a", 1)).toBe(true);
    expect(limiter.take("a", 1)).toBe(false);
    expect(limiter.take("b", 1)).toBe(true);
  });

  it("treats a limit of 0 as unlimited", () => {
    const limiter = new RateLimiter(() => 0);
    for (let i = 0; i < 100; i++) expect(limiter.take("tool", 0)).toBe(true);
  });
});
