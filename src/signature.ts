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
 * Timestamped signature scheme (the pattern used by Stripe and many others):
 *
 *   header:  X-Webhook-Signature: t=1700000000,v1=<hex>[,v1=<hex>...]
 *   signed:  HMAC-SHA256( secret, `${t}.${rawBody}` ), hex-encoded
 *
 * Binding the timestamp into the signed string is what makes replay protection possible:
 * an attacker cannot change `t` without invalidating the signature.
 */
export const DEFAULT_SIGNATURE_HEADER = "x-webhook-signature";
export const DEFAULT_TOLERANCE_SECONDS = 300;

const SHA256_BYTES = 32;

export interface SignOptions {
  secret: Secret;
  body: RawBody;
  /** Unix seconds. Defaults to now. */
  timestamp?: number;
}

export interface SignedPayload {
  timestamp: number;
  signature: string;
  /** Ready to send as the signature header value. */
  header: string;
}

export function computeSignature(secret: Secret, timestamp: number, body: RawBody): string {
  const [key] = normalizeSecrets(secret);
  return hmac("sha256", key as Buffer, Buffer.from(`${timestamp}.`, "utf8"), toBuffer(body)).toString("hex");
}

/** Sender side. Useful for tests, examples and for services that send webhooks. */
export function signPayload({ secret, body, timestamp }: SignOptions): SignedPayload {
  const t = timestamp ?? Math.floor(Date.now() / 1000);
  const signature = computeSignature(secret, t, body);
  return { timestamp: t, signature, header: `t=${t},v1=${signature}` };
}

export interface ParsedSignatureHeader {
  timestamp: number;
  signatures: Buffer[];
}

/**
 * Parse `t=...,v1=...`. Unknown keys are ignored so the scheme can evolve (a future v2).
 * Multiple `v1` values are allowed, which lets a sender sign with two secrets during rotation.
 */
export function parseSignatureHeader(header: string): ParsedSignatureHeader {
  let timestamp: number | undefined;
  const signatures: Buffer[] = [];

  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) {
      timestamp = Number(value);
    } else if (key === "v1") {
      const decoded = decodeHex(value, SHA256_BYTES);
      if (decoded) signatures.push(decoded);
    }
  }

  if (timestamp === undefined || signatures.length === 0) {
    throw new WebhookVerificationError(
      "malformed_signature",
      "Signature header must contain a numeric t= and at least one valid v1= value.",
    );
  }
  return { timestamp, signatures };
}

export interface VerifyOptions {
  /** One secret, or several during rotation (the old and the new). */
  secrets: Secret | readonly Secret[];
  /** Maximum clock difference in seconds, in either direction. Default 300. */
  tolerance?: number;
  /** Unix seconds. Injectable for tests. Defaults to now. */
  now?: number;
}

export interface VerifiedSignature {
  timestamp: number;
}

/**
 * Verify a webhook against its raw body. Throws WebhookVerificationError on any failure.
 *
 * Order matters: the signature is checked before the timestamp, so an unauthenticated
 * caller can only ever learn "signature_mismatch" and never probe the clock window.
 *
 * IMPORTANT: `body` must be the exact bytes received. Parsing the JSON and serializing it
 * again changes whitespace and key order, which breaks the signature.
 */
export function verifySignature(body: RawBody, header: HeaderValue, options: VerifyOptions): VerifiedSignature {
  const keys = normalizeSecrets(options.secrets);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  if (!(tolerance > 0)) throw new TypeError("tolerance must be a positive number of seconds");

  const raw = headerToString(header);
  if (raw === undefined) {
    throw new WebhookVerificationError("missing_signature", "The signature header is missing.");
  }

  const { timestamp, signatures } = parseSignatureHeader(raw);
  const payload = toBuffer(body);
  const prefix = Buffer.from(`${timestamp}.`, "utf8");
  const expected = keys.map((key) => hmac("sha256", key, prefix, payload));

  if (!anyEqual(signatures, expected)) {
    throw new WebhookVerificationError("signature_mismatch", "The signature does not match the payload.");
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > tolerance) {
    throw new WebhookVerificationError(
      "timestamp_outside_tolerance",
      `The timestamp is more than ${tolerance} seconds from the current time.`,
    );
  }

  return { timestamp };
}
