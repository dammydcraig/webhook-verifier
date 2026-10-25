import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import {
  WebhookVerificationError,
  computeSignature,
  parseSignatureHeader,
  signPayload,
  verifySignature,
  type VerificationErrorCode,
} from "../src/index.js";

const SECRET = "whsec_test_secret";
const NOW = 1_700_000_000;
const BODY = JSON.stringify({ id: "evt_1", type: "payment.succeeded", amount: 500000, currency: "NGN" });

function rejectsWith(code: VerificationErrorCode, fn: () => unknown): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof WebhookVerificationError, "expected a WebhookVerificationError");
    assert.equal(error.code, code);
    return true;
  });
}

const signedAt = (timestamp: number, body = BODY, secret = SECRET) => signPayload({ secret, body, timestamp }).header;

describe("verifySignature", () => {
  it("accepts a correctly signed payload", () => {
    const result = verifySignature(BODY, signedAt(NOW), { secrets: SECRET, now: NOW });
    assert.deepEqual(result, { timestamp: NOW });
  });

  it("matches an independent HMAC-SHA256 computed with node:crypto over `${t}.${body}`", () => {
    const expected = createHmac("sha256", SECRET).update(`${NOW}.${BODY}`).digest("hex");
    assert.equal(computeSignature(SECRET, NOW, BODY), expected);
  });

  it("signs the UTF-8 bytes, so strings and Buffers verify identically", () => {
    const body = JSON.stringify({ id: "evt_2", type: "payment.succeeded", note: "₦5,000 received, café" });
    const header = signedAt(NOW, body);
    verifySignature(body, header, { secrets: SECRET, now: NOW });
    verifySignature(Buffer.from(body, "utf8"), header, { secrets: SECRET, now: NOW });
  });

  it("rejects a tampered body", () => {
    const tampered = BODY.replace("500000", "900000");
    rejectsWith("signature_mismatch", () => verifySignature(tampered, signedAt(NOW), { secrets: SECRET, now: NOW }));
  });

  it("rejects a signature made with the wrong secret", () => {
    const header = signedAt(NOW, BODY, "some_other_secret");
    rejectsWith("signature_mismatch", () => verifySignature(BODY, header, { secrets: SECRET, now: NOW }));
  });

  it("binds the timestamp into the signature, so a replay cannot be refreshed", () => {
    const { signature } = signPayload({ secret: SECRET, body: BODY, timestamp: NOW - 10_000 });
    const refreshed = `t=${NOW},v1=${signature}`;
    rejectsWith("signature_mismatch", () => verifySignature(BODY, refreshed, { secrets: SECRET, now: NOW }));
  });

  it("verifies the raw bytes: re-serialized JSON does not verify", () => {
    const raw = '{"id": "evt_3",  "type": "payment.succeeded"}'; // note the spacing
    const header = signedAt(NOW, raw);
    verifySignature(raw, header, { secrets: SECRET, now: NOW });
    const reserialized = JSON.stringify(JSON.parse(raw));
    assert.notEqual(reserialized, raw);
    rejectsWith("signature_mismatch", () => verifySignature(reserialized, header, { secrets: SECRET, now: NOW }));
  });

  it("reports a missing header however it is empty", () => {
    for (const header of [undefined, "", "   ", []]) {
      rejectsWith("missing_signature", () => verifySignature(BODY, header, { secrets: SECRET, now: NOW }));
    }
  });

  it("accepts a header delivered as an array of values", () => {
    verifySignature(BODY, [signedAt(NOW)], { secrets: SECRET, now: NOW });
  });

  it("rejects malformed headers", () => {
    const valid = computeSignature(SECRET, NOW, BODY);
    const malformed = [
      "garbage",
      `t=abc,v1=${valid}`,
      `t=${NOW}`,
      `t=${NOW},v1=zz${valid.slice(2)}`,
      `t=${NOW},v1=${valid.slice(0, 40)}`,
      `v1=${valid}`,
      `t=-5,v1=${valid}`,
      `t=${NOW}.5,v1=${valid}`,
    ];
    for (const header of malformed) {
      rejectsWith("malformed_signature", () => verifySignature(BODY, header, { secrets: SECRET, now: NOW }));
    }
  });

  it("ignores unknown keys so the scheme can evolve", () => {
    const valid = computeSignature(SECRET, NOW, BODY);
    verifySignature(BODY, `t=${NOW},v0=deadbeef,v1=${valid},extra=1`, { secrets: SECRET, now: NOW });
  });
});

describe("replay window", () => {
  it("accepts timestamps at the edge of the tolerance and rejects just beyond it", () => {
    const options = { secrets: SECRET, now: NOW, tolerance: 300 };
    verifySignature(BODY, signedAt(NOW - 300), options);
    verifySignature(BODY, signedAt(NOW + 300), options);
    rejectsWith("timestamp_outside_tolerance", () => verifySignature(BODY, signedAt(NOW - 301), options));
    rejectsWith("timestamp_outside_tolerance", () => verifySignature(BODY, signedAt(NOW + 301), options));
  });

  it("rejects a validly signed but old request (a replay)", () => {
    const captured = signedAt(NOW - 3600);
    rejectsWith("timestamp_outside_tolerance", () =>
      verifySignature(BODY, captured, { secrets: SECRET, now: NOW }),
    );
  });

  it("honours a custom tolerance", () => {
    rejectsWith("timestamp_outside_tolerance", () =>
      verifySignature(BODY, signedAt(NOW - 11), { secrets: SECRET, now: NOW, tolerance: 10 }),
    );
    verifySignature(BODY, signedAt(NOW - 10), { secrets: SECRET, now: NOW, tolerance: 10 });
  });

  it("refuses a nonsensical tolerance instead of silently disabling the check", () => {
    for (const tolerance of [0, -1, Number.NaN]) {
      assert.throws(() => verifySignature(BODY, signedAt(NOW), { secrets: SECRET, now: NOW, tolerance }), TypeError);
    }
  });

  it("reveals only signature_mismatch to a caller who cannot sign, even with an old timestamp", () => {
    const forgedAndOld = signedAt(NOW - 10_000, BODY, "attacker_guess");
    rejectsWith("signature_mismatch", () => verifySignature(BODY, forgedAndOld, { secrets: SECRET, now: NOW }));
  });
});

describe("secret rotation", () => {
  const OLD = "whsec_old";
  const NEW = "whsec_new";

  it("accepts signatures from either secret while both are configured", () => {
    const options = { secrets: [NEW, OLD], now: NOW };
    verifySignature(BODY, signedAt(NOW, BODY, OLD), options);
    verifySignature(BODY, signedAt(NOW, BODY, NEW), options);
  });

  it("stops accepting the old secret once it is removed", () => {
    rejectsWith("signature_mismatch", () =>
      verifySignature(BODY, signedAt(NOW, BODY, OLD), { secrets: [NEW], now: NOW }),
    );
  });

  it("accepts a header carrying several v1 signatures if any one matches", () => {
    const withOld = computeSignature(OLD, NOW, BODY);
    const withNew = computeSignature(NEW, NOW, BODY);
    verifySignature(BODY, `t=${NOW},v1=${withOld},v1=${withNew}`, { secrets: NEW, now: NOW });
  });

  it("parses all v1 values", () => {
    const a = computeSignature(OLD, NOW, BODY);
    const b = computeSignature(NEW, NOW, BODY);
    const parsed = parseSignatureHeader(`t=${NOW},v1=${a},v1=${b}`);
    assert.equal(parsed.timestamp, NOW);
    assert.equal(parsed.signatures.length, 2);
  });
});

describe("fails closed on missing configuration", () => {
  it("never verifies with an empty secret", () => {
    // An HMAC keyed with "" is perfectly computable, so an unset env var could otherwise "work".
    const header = `t=${NOW},v1=${createHmac("sha256", "").update(`${NOW}.${BODY}`).digest("hex")}`;
    for (const secrets of ["", [], ["real_secret", ""]] as const) {
      rejectsWith("no_secret_configured", () => verifySignature(BODY, header, { secrets, now: NOW }));
    }
  });

  it("reports misconfiguration even when the header is also missing", () => {
    rejectsWith("no_secret_configured", () => verifySignature(BODY, undefined, { secrets: "", now: NOW }));
  });
});
