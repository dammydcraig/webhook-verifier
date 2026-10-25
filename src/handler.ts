import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import { WebhookVerificationError } from "./errors.js";
import { InMemoryIdempotencyStore, processOnce, type IdempotencyStore } from "./idempotency.js";
import type { Secret } from "./internal.js";
import { PAYSTACK_SIGNATURE_HEADER, verifyPaystackSignature } from "./paystack.js";
import { DEFAULT_SIGNATURE_HEADER, DEFAULT_TOLERANCE_SECONDS, verifySignature } from "./signature.js";

/** Throws WebhookVerificationError if the request is not authentic. */
export type Verifier = (rawBody: Buffer, headers: IncomingHttpHeaders) => void;

export interface TimestampedVerifierOptions {
  secrets: Secret | readonly Secret[];
  tolerance?: number;
  header?: string;
  /** Unix seconds. Injectable for tests. */
  now?: () => number;
}

export function timestampedVerifier(options: TimestampedVerifierOptions): Verifier {
  const header = (options.header ?? DEFAULT_SIGNATURE_HEADER).toLowerCase();
  return (rawBody, headers) => {
    verifySignature(rawBody, headers[header], {
      secrets: options.secrets,
      tolerance: options.tolerance ?? DEFAULT_TOLERANCE_SECONDS,
      ...(options.now ? { now: options.now() } : {}),
    });
  };
}

export function paystackVerifier(options: { secrets: Secret | readonly Secret[] }): Verifier {
  return (rawBody, headers) => {
    verifyPaystackSignature(rawBody, headers[PAYSTACK_SIGNATURE_HEADER], options.secrets);
  };
}

/** The normalized shape handed to your code, whatever the provider's payload looks like. */
export interface WebhookEvent {
  /** Stable identity used for de-duplication. */
  id: string;
  type: string;
  /** The parsed JSON body. */
  payload: Record<string, unknown>;
}

export type EventParser = (payload: Record<string, unknown>) => { id: string; type: string } | undefined;

/** Default: payloads shaped like `{ "id": "evt_123", "type": "payment.succeeded", ... }`. */
export const defaultEventParser: EventParser = (payload) => {
  const { id, type } = payload;
  if ((typeof id === "string" && id !== "") || typeof id === "number") {
    if (typeof type === "string" && type !== "") return { id: String(id), type };
  }
  return undefined;
};

/**
 * Paystack payloads look like `{ "event": "charge.success", "data": { "id": 302961, ... } }`
 * and carry no event id, so identity is the event name plus the object's id or reference.
 */
export const paystackEventParser: EventParser = (payload) => {
  const { event, data } = payload;
  if (typeof event !== "string" || event === "" || typeof data !== "object" || data === null) return undefined;
  const { id, reference } = data as Record<string, unknown>;
  const key = typeof id === "number" || typeof id === "string" ? id : reference;
  if (typeof key === "string" || typeof key === "number") {
    if (String(key) !== "") return { id: `${event}:${key}`, type: event };
  }
  return undefined;
};

export type LogLevel = "info" | "warn" | "error";
export type Logger = (level: LogLevel, message: string, meta?: Record<string, unknown>) => void;

export interface HandlerOptions {
  verify: Verifier;
  /** Your business logic. Throw to signal failure; the provider will retry. */
  onEvent: (event: WebhookEvent) => void | Promise<void>;
  parseEvent?: EventParser;
  /** Defaults to a per-process in-memory store. Use a shared store in production. */
  store?: IdempotencyStore;
  /** Reject bodies larger than this. Default 1 MB. */
  maxBodyBytes?: number;
  logger?: Logger;
}

const DEFAULT_MAX_BODY_BYTES = 1_000_000;

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
    ...headers,
  });
  res.end(text);
}

type BodyResult = { ok: true; body: Buffer } | { ok: false };

/** Collect the raw bytes without ever decoding or parsing them. Over-limit bodies are drained, not buffered. */
function readRawBody(req: IncomingMessage, limit: number): Promise<BodyResult> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let exceeded = false;
    req.on("data", (chunk: Buffer) => {
      if (exceeded) return;
      size += chunk.length;
      if (size > limit) {
        exceeded = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(exceeded ? { ok: false } : { ok: true, body: Buffer.concat(chunks, size) }));
    req.on("error", reject);
  });
}

/**
 * Response codes are chosen for how providers retry:
 *   200 processed or already processed   -> provider stops retrying
 *   401 bad signature                    -> same generic answer for every cause
 *   400 unreadable or unrecognised event -> retrying cannot help
 *   409 same event is mid-processing     -> retry later (Retry-After)
 *   500 your handler failed              -> retry; the claim is released so the retry can succeed
 */
export function createWebhookHandler(options: HandlerOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const store = options.store ?? new InMemoryIdempotencyStore();
  const parseEvent = options.parseEvent ?? defaultEventParser;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const log: Logger = options.logger ?? (() => {});

  return async (req, res) => {
    try {
      if (req.method !== "POST") {
        return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
      }

      const declared = Number(req.headers["content-length"]);
      if (Number.isFinite(declared) && declared > maxBodyBytes) {
        return sendJson(res, 413, { error: "payload_too_large" }, { connection: "close" });
      }

      const raw = await readRawBody(req, maxBodyBytes);
      if (!raw.ok) {
        return sendJson(res, 413, { error: "payload_too_large" }, { connection: "close" });
      }

      try {
        options.verify(raw.body, req.headers);
      } catch (error) {
        if (error instanceof WebhookVerificationError) {
          if (error.code === "no_secret_configured") {
            log("error", "webhook secret is not configured", { code: error.code });
            return sendJson(res, 500, { error: "server_misconfigured" });
          }
          // The reason is logged for you but never revealed to the sender.
          log("warn", "webhook rejected", { code: error.code });
          return sendJson(res, 401, { error: "invalid_signature" });
        }
        throw error;
      }

      let payload: unknown;
      try {
        payload = JSON.parse(raw.body.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "invalid_json" });
      }
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        return sendJson(res, 400, { error: "invalid_event" });
      }

      const identity = parseEvent(payload as Record<string, unknown>);
      if (!identity) return sendJson(res, 400, { error: "invalid_event" });
      const event: WebhookEvent = { ...identity, payload: payload as Record<string, unknown> };

      const result = await processOnce(store, `event:${event.id}`, () => options.onEvent(event));
      switch (result.outcome) {
        case "processed":
          log("info", "webhook processed", { id: event.id, type: event.type });
          return sendJson(res, 200, { status: "processed" });
        case "duplicate":
          log("info", "duplicate webhook ignored", { id: event.id, type: event.type });
          return sendJson(res, 200, { status: "duplicate" });
        case "in_progress":
          return sendJson(res, 409, { status: "in_progress" }, { "retry-after": "5" });
      }
    } catch (error) {
      log("error", "webhook handler failed", { message: error instanceof Error ? error.message : String(error) });
      if (!res.headersSent) sendJson(res, 500, { error: "processing_failed" });
    }
  };
}
