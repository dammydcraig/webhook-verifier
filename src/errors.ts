/**
 * Every verification failure is a typed error with a stable `code`, so callers can log
 * the reason internally while returning the same generic response to the sender.
 */
export type VerificationErrorCode =
  | "missing_signature"
  | "malformed_signature"
  | "timestamp_outside_tolerance"
  | "signature_mismatch"
  | "no_secret_configured";

export class WebhookVerificationError extends Error {
  readonly code: VerificationErrorCode;

  constructor(code: VerificationErrorCode, message: string) {
    super(message);
    this.name = "WebhookVerificationError";
    this.code = code;
  }
}
