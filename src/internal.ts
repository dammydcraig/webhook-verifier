import { createHmac, timingSafeEqual } from "node:crypto";
import { WebhookVerificationError } from "./errors.js";

export type Secret = string | Buffer;
export type RawBody = string | Uint8Array;
export type HeaderValue = string | string[] | undefined;

export function toBuffer(body: RawBody): Buffer {
  return typeof body === "string"
    ? Buffer.from(body, "utf8")
    : Buffer.from(body.buffer, body.byteOffset, body.byteLength);
}

/**
 * Fail closed: an empty or missing secret would still produce a "valid" HMAC, so a
 * misconfigured environment variable must never be allowed to verify anything.
 */
export function normalizeSecrets(secrets: Secret | readonly Secret[]): Buffer[] {
  const list: readonly Secret[] = Array.isArray(secrets) ? (secrets as readonly Secret[]) : [secrets as Secret];
  const keys = list.map((s) => (typeof s === "string" ? Buffer.from(s, "utf8") : s));
  if (keys.length === 0 || keys.some((k) => k.length === 0)) {
    throw new WebhookVerificationError(
      "no_secret_configured",
      "At least one non-empty signing secret is required, and none may be empty.",
    );
  }
  return keys;
}

export function headerToString(header: HeaderValue): string | undefined {
  const value = Array.isArray(header) ? header.join(",") : header;
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

export function hmac(algorithm: "sha256" | "sha512", key: Buffer, ...parts: Buffer[]): Buffer {
  const h = createHmac(algorithm, key);
  for (const part of parts) h.update(part);
  return h.digest();
}

/** Decode hex of an exact byte length, or return undefined if it is not valid hex of that size. */
export function decodeHex(hex: string, byteLength: number): Buffer | undefined {
  if (hex.length !== byteLength * 2 || !/^[0-9a-fA-F]+$/.test(hex)) return undefined;
  return Buffer.from(hex, "hex");
}

/**
 * True if any candidate equals any expected value. Every pair is compared with
 * timingSafeEqual and there is no early exit, so timing reveals neither which secret
 * nor which signature matched.
 */
export function anyEqual(candidates: readonly Buffer[], expected: readonly Buffer[]): boolean {
  let matched = false;
  for (const e of expected) {
    for (const c of candidates) {
      if (c.length === e.length && timingSafeEqual(c, e)) matched = true;
    }
  }
  return matched;
}
