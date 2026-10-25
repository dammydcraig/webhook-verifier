/**
 * Plays the part of the payment provider, so you can see what the receiver does with
 * good deliveries, retries, forgeries and replays.
 *
 *   WEBHOOK_SECRET=demo_secret npm run example:send
 */
import { signPayload } from "../src/index.js";

const secret = process.env.WEBHOOK_SECRET;
if (!secret) {
  console.error("Set WEBHOOK_SECRET to the same value the server uses.");
  process.exit(1);
}
const url = process.env.WEBHOOK_URL ?? "http://127.0.0.1:3000/webhooks";

const body = JSON.stringify({
  id: "evt_1001",
  type: "payment.succeeded",
  data: { account: "acct_001", amount: 500000, currency: "NGN" },
});

async function deliver(label: string, payload: string, header: string): Promise<void> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "x-webhook-signature": header },
    body: payload,
  });
  console.log(`${label.padEnd(44)} -> ${res.status} ${await res.text()}`);
}

const now = Math.floor(Date.now() / 1000);

await deliver("1. genuine delivery", body, signPayload({ secret, body }).header);
await deliver("2. provider retries the same event", body, signPayload({ secret, body }).header);
await deliver(
  "3. attacker changes the amount",
  body.replace("500000", "900000000"),
  signPayload({ secret, body }).header,
);
await deliver("4. attacker signs with a guessed secret", body, signPayload({ secret: "guess", body }).header);
await deliver("5. replay of a captured request, 1 hour old", body, signPayload({ secret, body, timestamp: now - 3600 }).header);
await deliver("6. no signature header at all", body, "");
