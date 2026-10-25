import { createHash, randomBytes } from "node:crypto";

/**
 * 32 CSPRNG bytes, base64url encoded. Always 43 chars, no padding.
 * This format is persisted by the issuing service: do not change it.
 */
export function createSessionToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * SHA-256 of the UTF-8 token, base64url encoded. Deterministic, 43 chars.
 * This output is the persisted store key: changing it invalidates every live
 * session and requires a dual-read migration.
 */
export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("base64url");
}

/** Shape every valid session token must match. Checked before any store call. */
export const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
