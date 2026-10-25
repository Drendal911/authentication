/** Internal denial taxonomy mapped to status codes and headers. */
export type DenialReason =
  | "missing"
  | "malformed"
  | "unknown"
  | "expired"
  | "store_error"
  | "insufficient_scope";

export interface Denial {
  status: 401 | 403 | 503;
  body: { error: "unauthorized" | "forbidden" | "temporarily_unavailable" };
  /** WWW-Authenticate challenge, or undefined when none applies. */
  challenge?: string;
  reason: DenialReason;
}

export function denialFor(reason: DenialReason, realm: string): Denial {
  switch (reason) {
    case "missing":
      return { status: 401, body: { error: "unauthorized" }, challenge: `Bearer realm="${realm}"`, reason };
    case "malformed":
    case "unknown":
    case "expired":
      return {
        status: 401,
        body: { error: "unauthorized" },
        challenge: `Bearer realm="${realm}", error="invalid_token"`,
        reason,
      };
    case "insufficient_scope":
      return {
        status: 403,
        body: { error: "forbidden" },
        challenge: `Bearer realm="${realm}", error="insufficient_scope"`,
        reason,
      };
    case "store_error":
      return { status: 503, body: { error: "temporarily_unavailable" }, reason };
  }
}
