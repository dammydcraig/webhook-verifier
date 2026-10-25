import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import {
  WebhookVerificationError,
  computePaystackSignature,
  verifyPaystackSignature,
  type VerificationErrorCode,
} from "../src/index.js";

const SECRET = "sk_test_example_key";
const BODY = JSON.stringify({ event: "charge.success", data: { id: 302961, reference: "ref_123", amount: 500000 } });

function rejectsWith(code: VerificationErrorCode, fn: () => unknown): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof WebhookVerificationError);
    assert.equal(error.code, code);
    return true;
  });
}

const sign = (body: string, secret = SECRET) => createHmac("sha512", secret).update(body).digest("hex");

describe("verifyPaystackSignature", () => {
  it("accepts HMAC-SHA512 of the raw body, hex-encoded (independent oracle)", () => {
    verifyPaystackSignature(BODY, sign(BODY), SECRET);
    assert.equal(computePaystackSignature(SECRET, BODY), sign(BODY));
  });

  it("accepts Buffers and upper-case hex", () => {
    verifyPaystackSignature(Buffer.from(BODY), sign(BODY).toUpperCase(), SECRET);
  });

  it("rejects a tampered body", () => {
    rejectsWith("signature_mismatch", () =>
      verifyPaystackSignature(BODY.replace("500000", "1"), sign(BODY), SECRET),
    );
  });

  it("rejects the wrong secret", () => {
    rejectsWith("signature_mismatch", () => verifyPaystackSignature(BODY, sign(BODY, "sk_test_other"), SECRET));
  });

  it("supports key rotation with several secrets", () => {
    verifyPaystackSignature(BODY, sign(BODY, "sk_test_old"), ["sk_test_new", "sk_test_old"]);
  });

  it("reports a missing header", () => {
    rejectsWith("missing_signature", () => verifyPaystackSignature(BODY, undefined, SECRET));
    rejectsWith("missing_signature", () => verifyPaystackSignature(BODY, "", SECRET));
  });

  it("rejects headers that are not 128 hex characters, including a SHA-256 length digest", () => {
    const sha256 = createHmac("sha256", SECRET).update(BODY).digest("hex");
    for (const header of ["not-hex", sign(BODY).slice(0, 100), sha256, `${sign(BODY)}00`]) {
      rejectsWith("malformed_signature", () => verifyPaystackSignature(BODY, header, SECRET));
    }
  });

  it("fails closed when no secret is configured", () => {
    const forgedWithEmptyKey = sign(BODY, "");
    rejectsWith("no_secret_configured", () => verifyPaystackSignature(BODY, forgedWithEmptyKey, ""));
    rejectsWith("no_secret_configured", () => verifyPaystackSignature(BODY, forgedWithEmptyKey, []));
  });
});
