import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, it } from "node:test";
import {
  createWebhookHandler,
  paystackEventParser,
  paystackVerifier,
  signPayload,
  timestampedVerifier,
  type HandlerOptions,
  type WebhookEvent,
} from "../src/index.js";

const SECRET = "whsec_handler_secret";
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const servers: Server[] = [];
after(() => {
  for (const server of servers) server.close();
});

interface Harness {
  url: string;
  events: WebhookEvent[];
  logs: Array<{ level: string; message: string; meta?: Record<string, unknown> | undefined }>;
}

async function start(overrides: Partial<HandlerOptions> = {}, secrets: string | string[] = SECRET): Promise<Harness> {
  const events: WebhookEvent[] = [];
  const logs: Harness["logs"] = [];
  const handler = createWebhookHandler({
    verify: timestampedVerifier({ secrets }),
    onEvent: (event) => {
      events.push(event);
    },
    logger: (level, message, meta) => logs.push({ level, message, meta }),
    ...overrides,
  });
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/webhooks`, events, logs };
}

const eventBody = (id = "evt_1", extra: Record<string, unknown> = {}) =>
  JSON.stringify({ id, type: "payment.succeeded", data: { amount: 500000, currency: "NGN" }, ...extra });

async function post(url: string, body: string, headers: Record<string, string> = {}) {
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
  return { status: response.status, headers: response.headers, json: (await response.json()) as Record<string, unknown> };
}

const signedPost = (url: string, body: string, secret = SECRET, timestamp?: number) =>
  post(url, body, { "x-webhook-signature": signPayload({ secret, body, ...(timestamp ? { timestamp } : {}) }).header });

describe("webhook handler", () => {
  it("processes a correctly signed event and hands your code the parsed event", async () => {
    const h = await start();
    const res = await signedPost(h.url, eventBody("evt_1"));
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { status: "processed" });
    assert.equal(h.events.length, 1);
    assert.equal(h.events[0]?.id, "evt_1");
    assert.equal(h.events[0]?.type, "payment.succeeded");
    assert.deepEqual(h.events[0]?.payload.data, { amount: 500000, currency: "NGN" });
  });

  it("acknowledges a redelivered event with 200 but does not run your code twice", async () => {
    const h = await start();
    const body = eventBody("evt_dup");
    const first = await signedPost(h.url, body);
    const second = await signedPost(h.url, body); // provider retry: same event, fresh signature
    assert.equal(first.json.status, "processed");
    assert.equal(second.status, 200);
    assert.equal(second.json.status, "duplicate");
    assert.equal(h.events.length, 1);
  });

  it("rejects a wrong signature with 401 and runs nothing", async () => {
    const h = await start();
    const res = await signedPost(h.url, eventBody(), "attacker_secret");
    assert.equal(res.status, 401);
    assert.deepEqual(res.json, { error: "invalid_signature" });
    assert.equal(h.events.length, 0);
  });

  it("rejects a tampered body", async () => {
    const h = await start();
    const body = eventBody();
    const { header } = signPayload({ secret: SECRET, body });
    const res = await post(h.url, body.replace("500000", "50000000"), { "x-webhook-signature": header });
    assert.equal(res.status, 401);
    assert.equal(h.events.length, 0);
  });

  it("rejects a replayed request whose signature is valid but old", async () => {
    const h = await start();
    const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
    const res = await signedPost(h.url, eventBody(), SECRET, oneHourAgo);
    assert.equal(res.status, 401);
    assert.equal(h.events.length, 0);
  });

  it("gives the sender the same answer for every kind of failure, and logs the real reason", async () => {
    const h = await start();
    const body = eventBody();
    const old = Math.floor(Date.now() / 1000) - 3600;
    const attempts = [
      await post(h.url, body), // missing header
      await post(h.url, body, { "x-webhook-signature": "garbage" }), // malformed
      await signedPost(h.url, body, "wrong"), // mismatch
      await signedPost(h.url, body, SECRET, old), // stale
    ];
    for (const res of attempts) {
      assert.equal(res.status, 401);
      assert.deepEqual(res.json, { error: "invalid_signature" });
    }
    const codes = h.logs.filter((l) => l.level === "warn").map((l) => l.meta?.code);
    assert.deepEqual(codes, ["missing_signature", "malformed_signature", "signature_mismatch", "timestamp_outside_tolerance"]);
  });

  it("does not let a forged copy of an event block the genuine delivery", async () => {
    const h = await start();
    const body = eventBody("evt_race");
    const forged = await signedPost(h.url, body, "attacker_secret");
    assert.equal(forged.status, 401);
    const genuine = await signedPost(h.url, body);
    assert.equal(genuine.status, 200);
    assert.equal(genuine.json.status, "processed");
    assert.equal(h.events.length, 1);
  });

  it("verifies the raw bytes, not a re-serialized copy", async () => {
    const h = await start();
    const raw = '{ "id":"evt_raw",\n  "type" : "payment.succeeded", "note":"₦5,000 café" }';
    const res = await signedPost(h.url, raw);
    assert.equal(res.status, 200);
    assert.equal(h.events[0]?.payload.note, "₦5,000 café");
  });

  it("only accepts POST", async () => {
    const h = await start();
    const res = await fetch(h.url, { method: "GET" });
    assert.equal(res.status, 405);
    assert.equal(res.headers.get("allow"), "POST");
  });

  it("returns 400 for a signed but unreadable or unrecognised body", async () => {
    const h = await start();
    for (const body of ["not json", "[1,2,3]", "null", JSON.stringify({ type: "no.id" }), JSON.stringify({ id: "x" }), JSON.stringify({ id: "", type: "t" })]) {
      const res = await signedPost(h.url, body);
      assert.equal(res.status, 400, `body ${body} should be rejected`);
    }
    assert.equal(h.events.length, 0);
  });

  it("rejects a body over the limit when its size is declared", async () => {
    const h = await start({ maxBodyBytes: 1_000 });
    const res = await signedPost(h.url, eventBody("evt_big", { padding: "x".repeat(5_000) }));
    assert.equal(res.status, 413);
    assert.equal(h.events.length, 0);
  });

  it("rejects an over-limit body even when it is streamed without a content-length", async () => {
    const h = await start({ maxBodyBytes: 1_000 });
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(h.url, { method: "POST", headers: { "transfer-encoding": "chunked" } }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      });
      req.on("error", reject);
      for (let i = 0; i < 3; i++) req.write("y".repeat(600));
      req.end();
    });
    assert.equal(status, 413);
    assert.equal(h.events.length, 0);
  });

  it("answers 500 when your code fails, then accepts the provider's retry of the same event", async () => {
    let attempts = 0;
    const h = await start({
      onEvent: () => {
        attempts++;
        if (attempts === 1) throw new Error("database unavailable");
      },
    });
    const body = eventBody("evt_retry");
    const first = await signedPost(h.url, body);
    assert.equal(first.status, 500);
    assert.deepEqual(first.json, { error: "processing_failed" }, "internal error details must not leak");
    const retry = await signedPost(h.url, body);
    assert.equal(retry.status, 200);
    assert.equal(retry.json.status, "processed");
    assert.equal(attempts, 2);
    const third = await signedPost(h.url, body);
    assert.equal(third.json.status, "duplicate");
    assert.equal(attempts, 2);
  });

  it("answers 409 with Retry-After to a duplicate that arrives while the first is still running", async () => {
    let runs = 0;
    const h = await start({
      onEvent: async () => {
        runs++;
        await sleep(150);
      },
    });
    const body = eventBody("evt_concurrent");
    const [a, b] = await Promise.all([signedPost(h.url, body), signedPost(h.url, body)]);
    const results = [a, b].sort((x, y) => x.status - y.status);
    assert.equal(results[0]?.status, 200);
    assert.equal(results[0]?.json.status, "processed");
    assert.equal(results[1]?.status, 409);
    assert.equal(results[1]?.json.status, "in_progress");
    assert.equal(results[1]?.headers.get("retry-after"), "5");
    assert.equal(runs, 1);
    assert.equal((await signedPost(h.url, body)).json.status, "duplicate");
  });

  it("supports secret rotation: old and new secrets both verify", async () => {
    const h = await start({}, ["whsec_new", "whsec_old"]);
    assert.equal((await signedPost(h.url, eventBody("evt_a"), "whsec_old")).status, 200);
    assert.equal((await signedPost(h.url, eventBody("evt_b"), "whsec_new")).status, 200);
    assert.equal((await signedPost(h.url, eventBody("evt_c"), "whsec_retired")).status, 401);
  });

  it("fails closed with 500 if the secret is not configured, never accepting anything", async () => {
    const h = await start({}, "");
    const forged = createHmac("sha256", "").update(`${Math.floor(Date.now() / 1000)}.x`).digest("hex");
    const res = await post(h.url, eventBody(), { "x-webhook-signature": `t=${Math.floor(Date.now() / 1000)},v1=${forged}` });
    assert.equal(res.status, 500);
    assert.deepEqual(res.json, { error: "server_misconfigured" });
    assert.equal(h.events.length, 0);
    assert.ok(h.logs.some((l) => l.level === "error"));
  });
});

describe("webhook handler with the Paystack scheme", () => {
  const PAYSTACK_SECRET = "sk_test_paystack_secret";
  const body = JSON.stringify({ event: "charge.success", data: { id: 302961, reference: "ref_123", amount: 500000 } });
  const sign = (b: string, secret = PAYSTACK_SECRET) => createHmac("sha512", secret).update(b).digest("hex");

  async function startPaystack() {
    return start({ verify: paystackVerifier({ secrets: PAYSTACK_SECRET }), parseEvent: paystackEventParser });
  }

  it("verifies x-paystack-signature and de-duplicates by event and object id", async () => {
    const h = await startPaystack();
    const first = await post(h.url, body, { "x-paystack-signature": sign(body) });
    const second = await post(h.url, body, { "x-paystack-signature": sign(body) });
    assert.equal(first.json.status, "processed");
    assert.equal(second.json.status, "duplicate");
    assert.equal(h.events.length, 1);
    assert.equal(h.events[0]?.id, "charge.success:302961");
    assert.equal(h.events[0]?.type, "charge.success");
  });

  it("rejects a bad or missing signature", async () => {
    const h = await startPaystack();
    assert.equal((await post(h.url, body, { "x-paystack-signature": sign(body, "other") })).status, 401);
    assert.equal((await post(h.url, body)).status, 401);
    assert.equal(h.events.length, 0);
  });

  it("falls back to the reference when the object has no id", async () => {
    const h = await startPaystack();
    const refOnly = JSON.stringify({ event: "transfer.success", data: { reference: "trf_9" } });
    assert.equal((await post(h.url, refOnly, { "x-paystack-signature": sign(refOnly) })).status, 200);
    assert.equal(h.events[0]?.id, "transfer.success:trf_9");
  });
});
