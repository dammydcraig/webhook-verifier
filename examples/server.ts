/**
 * A tiny wallet-crediting webhook receiver.
 *
 *   WEBHOOK_SECRET=demo_secret npm run example:server
 *
 * During secret rotation, list both: WEBHOOK_SECRET=new_secret,old_secret
 */
import { createServer } from "node:http";
import { createWebhookHandler, timestampedVerifier } from "../src/index.js";

const raw = process.env.WEBHOOK_SECRET;
if (!raw) {
  console.error("Set WEBHOOK_SECRET, for example: WEBHOOK_SECRET=demo_secret npm run example:server");
  process.exit(1);
}
const secrets = raw.split(",").map((s) => s.trim()); // an empty entry fails closed (500), by design
const port = Number(process.env.PORT ?? 3000);

// Balances in kobo (NGN minor units), in memory. A real service would write ledger entries to a database.
const balances = new Map<string, number>();

const handler = createWebhookHandler({
  verify: timestampedVerifier({ secrets }),
  logger: (level, message, meta) => console.log(JSON.stringify({ level, message, ...meta })),
  onEvent: ({ id, type, payload }) => {
    if (type !== "payment.succeeded") return; // acknowledge events we do not act on

    const data = payload.data as { account?: unknown; amount?: unknown } | undefined;
    const account = data?.account;
    const amount = data?.amount;
    if (typeof account !== "string" || !Number.isSafeInteger(amount) || (amount as number) <= 0) {
      // A permanently malformed event will never succeed on retry. Record it and acknowledge
      // it, instead of throwing and inviting endless redelivery.
      console.log(JSON.stringify({ level: "warn", message: "ignoring malformed payment event", id }));
      return;
    }

    const balance = (balances.get(account) ?? 0) + (amount as number);
    balances.set(account, balance);
    console.log(JSON.stringify({ level: "info", message: "wallet credited", id, account, balance }));
  },
});

createServer((req, res) => {
  if (req.url === "/webhooks") return void handler(req, res);
  res.writeHead(404).end();
}).listen(port, () => console.log(`Listening on http://127.0.0.1:${port}/webhooks`));
