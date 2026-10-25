/**
 * Webhook providers deliver at least once. A timeout on your side, a 5xx, or a network blip
 * makes them send the same event again, so a handler that credits a wallet must be safe to
 * run twice. This module claims each event id before doing the work.
 *
 * States: claimed (you may process) -> done (never process again).
 * If processing fails, release the claim so the provider's retry can succeed.
 */
export type ClaimResult = "claimed" | "in_progress" | "done";

export interface IdempotencyStore {
  /** Atomically claim a key. Exactly one concurrent caller may receive "claimed". */
  begin(key: string): ClaimResult | Promise<ClaimResult>;
  /** Mark a claimed key as finished. Future begin() calls return "done". */
  complete(key: string): void | Promise<void>;
  /** Give up a claim after a failure so the event can be retried. */
  release(key: string): void | Promise<void>;
}

export interface InMemoryStoreOptions {
  /** How long a finished key is remembered. Default 24 hours. */
  ttlMs?: number;
  /** How long a claim is held before it is assumed abandoned (a crashed worker). Default 60 seconds. */
  inProgressTtlMs?: number;
  /** Upper bound on remembered keys. Oldest entries are evicted first. Default 10,000. */
  maxEntries?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

interface Entry {
  state: "in_progress" | "done";
  expiresAt: number;
}

/**
 * Demo and test store. It lives in one process's memory, so it forgets everything on restart
 * and does not coordinate between instances. In production use a shared store with an
 * atomic "insert if absent": a database unique constraint, or Redis SET NX with an expiry.
 */
export class InMemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<string, Entry>();
  private readonly ttlMs: number;
  private readonly inProgressTtlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: InMemoryStoreOptions = {}) {
    this.ttlMs = options.ttlMs ?? 24 * 60 * 60 * 1000;
    this.inProgressTtlMs = options.inProgressTtlMs ?? 60_000;
    this.maxEntries = options.maxEntries ?? 10_000;
    this.now = options.now ?? Date.now;
  }

  begin(key: string): ClaimResult {
    const existing = this.entries.get(key);
    if (existing && existing.expiresAt > this.now()) {
      return existing.state === "done" ? "done" : "in_progress";
    }
    this.set(key, { state: "in_progress", expiresAt: this.now() + this.inProgressTtlMs });
    return "claimed";
  }

  complete(key: string): void {
    this.set(key, { state: "done", expiresAt: this.now() + this.ttlMs });
  }

  release(key: string): void {
    this.entries.delete(key);
  }

  get size(): number {
    return this.entries.size;
  }

  private set(key: string, entry: Entry): void {
    this.entries.delete(key); // re-insert so Map order tracks recency
    this.entries.set(key, entry);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }
}

export type ProcessOutcome<T> =
  | { outcome: "processed"; result: T }
  | { outcome: "duplicate" }
  | { outcome: "in_progress" };

/**
 * Run `work` at most once per key.
 *  - processed:   this call did the work.
 *  - duplicate:   the work was already completed earlier. Answer 2xx so the provider stops retrying.
 *  - in_progress: another call is working on it right now. Answer with a retryable status.
 * If `work` throws, the claim is released and the error is re-thrown, so the retry can run.
 */
export async function processOnce<T>(
  store: IdempotencyStore,
  key: string,
  work: () => T | Promise<T>,
): Promise<ProcessOutcome<T>> {
  const claim = await store.begin(key);
  if (claim === "done") return { outcome: "duplicate" };
  if (claim === "in_progress") return { outcome: "in_progress" };

  try {
    const result = await work();
    await store.complete(key);
    return { outcome: "processed", result };
  } catch (error) {
    await store.release(key);
    throw error;
  }
}
