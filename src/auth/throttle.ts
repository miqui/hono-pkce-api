export interface ThrottleLimits {
  maxFailures: number;
  windowMs: number;
}

export const DEFAULT_LIMITS: ThrottleLimits = { maxFailures: 5, windowMs: 15 * 60_000 };

/** In-memory sliding-window failure counter keyed by arbitrary strings. */
export class FailureLimiter {
  private readonly fails = new Map<string, number[]>();

  constructor(
    private readonly limits: ThrottleLimits,
    private readonly now: () => number,
  ) {}

  private recent(key: string): number[] {
    const t = this.now();
    const list = (this.fails.get(key) ?? []).filter((ts) => ts > t - this.limits.windowMs);
    if (list.length) this.fails.set(key, list);
    else this.fails.delete(key);
    return list;
  }

  /** Seconds until the key may try again, or 0 when not blocked. */
  retryAfterSec(key: string): number {
    const list = this.recent(key);
    if (list.length < this.limits.maxFailures) return 0;
    return Math.max(1, Math.ceil((list[0]! + this.limits.windowMs - this.now()) / 1000));
  }

  fail(key: string): void {
    const list = this.recent(key);
    list.push(this.now());
    this.fails.set(key, list);
  }

  reset(key: string): void {
    this.fails.delete(key);
  }
}
