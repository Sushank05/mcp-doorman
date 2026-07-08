/**
 * Token-bucket rate limiting, keyed by namespaced tool name.
 *
 * A runaway or hijacked agent hammering a tool (mass-deleting, mass-mailing,
 * scraping) is a blast-radius problem: rate limits cap how much damage a
 * single misbehaving loop can do per minute.
 */

export class RateLimiter {
  private buckets = new Map<string, { tokens: number; last: number }>();

  constructor(private now: () => number = Date.now) {}

  /**
   * Try to take one token from `key`'s bucket, refilled continuously at
   * `perMinute` tokens/minute (also the burst capacity). A `perMinute`
   * of 0 or less disables limiting for that key.
   */
  take(key: string, perMinute: number): boolean {
    if (perMinute <= 0) return true;
    const t = this.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: perMinute, last: t };
      this.buckets.set(key, bucket);
    }
    const refill = ((t - bucket.last) / 60_000) * perMinute;
    bucket.tokens = Math.min(perMinute, bucket.tokens + refill);
    bucket.last = t;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    return false;
  }
}
