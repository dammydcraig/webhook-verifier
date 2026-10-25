import { WebhookVerificationError } from "./errors.js";
import {
  anyEqual,
  decodeHex,
  headerToString,
  hmac,
  normalizeSecrets,
  toBuffer,
  type HeaderValue,
  type RawBody,
  type Secret,
} from "./internal.js";

/**
 * Paystack signs the raw request body with HMAC-SHA512 using your secret key and sends the
 * hex digest in `x-paystack-signature`. (Described in third-party guides; always confirm
 * against Paystack's current documentation before relying on it in production.)
 *
 * This scheme has NO timestamp, so a captured, validly signed request can be replayed.
 * Pair it with idempotent event processing, and confirm important events with the
 * provider's API (for example, verify the transaction) before acting on them.
 */
export const PAYSTACK_SIGNATURE_HEADER = "x-paystack-signature";

const SHA512_BYTES = 64;

export function computePaystackSignature(secret: Secret, body: RawBody): string {
  const [key] = normalizeSecrets(secret);
  return hmac("sha512", key as Buffer, toBuffer(body)).toString("hex");
}

export function verifyPaystackSignature(
  body: RawBody,
  header: HeaderValue,
  secrets: Secret | readonly Secret[],
): void {
  const keys = normalizeSecrets(secrets);

  const raw = headerToString(header);
  if (raw === undefined) {
    throw new WebhookVerificationError("missing_signature", "The signature header is missing.");
  }
  const provided = decodeHex(raw, SHA512_BYTES);
  if (!provided) {
    throw new WebhookVerificationError("malformed_signature", "The signature must be 128 hex characters.");
  }

  const payload = toBuffer(body);
  const expected = keys.map((key) => hmac("sha512", key, payload));
  if (!anyEqual([provided], expected)) {
    throw new WebhookVerificationError("signature_mismatch", "The signature does not match the payload.");
  }
}
