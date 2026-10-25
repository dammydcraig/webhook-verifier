import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { InMemoryIdempotencyStore, processOnce } from "../src/index.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("processOnce", () => {
  it("does the work once and reports later deliveries as duplicates", async () => {
    const store = new InMemoryIdempotencyStore();
    let calls = 0;
    const work = () => ++calls;

    assert.deepEqual(await processOnce(store, "evt_1", work), { outcome: "processed", result: 1 });
    assert.deepEqual(await processOnce(store, "evt_1", work), { outcome: "duplicate" });
    assert.deepEqual(await processOnce(store, "evt_1", work), { outcome: "duplicate" });
    assert.equal(calls, 1);
  });

  it("treats different keys independently", async () => {
    const store = new InMemoryIdempotencyStore();
    let calls = 0;
    await processOnce(store, "evt_a", () => ++calls);
    await processOnce(store, "evt_b", () => ++calls);
    assert.equal(calls, 2);
  });

  it("lets only one of two simultaneous deliveries run", async () => {
    const store = new InMemoryIdempotencyStore();
    let calls = 0;
    const slow = async () => {
      calls++;
      await sleep(50);
    };

    const [a, b] = await Promise.all([processOnce(store, "evt_1", slow), processOnce(store, "evt_1", slow)]);
    const outcomes = [a.outcome, b.outcome].sort();
    assert.deepEqual(outcomes, ["in_progress", "processed"]);
    assert.equal(calls, 1);

    assert.equal((await processOnce(store, "evt_1", slow)).outcome, "duplicate");
    assert.equal(calls, 1);
  });

  it("releases the claim when the work fails, so the provider's retry can succeed", async () => {
    const store = new InMemoryIdempotencyStore();
    let attempts = 0;
    const flaky = () => {
      attempts++;
      if (attempts === 1) throw new Error("database unavailable");
      return "ok";
    };

    await assert.rejects(processOnce(store, "evt_1", flaky), /database unavailable/);
    assert.deepEqual(await processOnce(store, "evt_1", flaky), { outcome: "processed", result: "ok" });
    assert.equal(attempts, 2);
    assert.equal((await processOnce(store, "evt_1", flaky)).outcome, "duplicate");
  });

  it("releases the claim when async work rejects", async () => {
    const store = new InMemoryIdempotencyStore();
    await assert.rejects(
      processOnce(store, "evt_1", async () => {
        throw new Error("boom");
      }),
      /boom/,
    );
    assert.equal((await processOnce(store, "evt_1", () => "fine")).outcome, "processed");
  });
});

describe("InMemoryIdempotencyStore", () => {
  it("lets an abandoned claim expire, so a crashed worker cannot block an event forever", () => {
    let now = 1_000;
    const store = new InMemoryIdempotencyStore({ inProgressTtlMs: 60_000, now: () => now });
    assert.equal(store.begin("evt_1"), "claimed");
    assert.equal(store.begin("evt_1"), "in_progress");
    now += 59_999;
    assert.equal(store.begin("evt_1"), "in_progress");
    now += 2;
    assert.equal(store.begin("evt_1"), "claimed");
  });

  it("forgets completed keys after the TTL", () => {
    let now = 1_000;
    const store = new InMemoryIdempotencyStore({ ttlMs: 10_000, now: () => now });
    store.begin("evt_1");
    store.complete("evt_1");
    assert.equal(store.begin("evt_1"), "done");
    now += 10_001;
    assert.equal(store.begin("evt_1"), "claimed");
  });

  it("bounds memory by evicting the oldest keys", () => {
    const store = new InMemoryIdempotencyStore({ maxEntries: 2 });
    for (const key of ["a", "b", "c"]) {
      store.begin(key);
      store.complete(key);
    }
    assert.equal(store.size, 2);
    assert.equal(store.begin("a"), "claimed", "the oldest key was evicted");
    assert.equal(store.begin("c"), "done");
  });

  it("ignores release of an unknown key", () => {
    const store = new InMemoryIdempotencyStore();
    assert.doesNotThrow(() => store.release("never_seen"));
  });
});
