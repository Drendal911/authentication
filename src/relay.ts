import type { Request } from "express";
import { SESSION_TOKEN_PATTERN } from "./tokens.js";

/**
 * Headers that forward the caller's existing credential, or {} if absent or
 * malformed. Relay only to trusted internal services on this host. Never relay
 * to a third party, never mint a derived token, and never log the result.
 * Loopback origin is not identity; do not treat 127.0.0.1 as authenticated.
 */
export function forwardAuth(req: Request): Record<string, string> {
  const header = req.headers.authorization;
  if (typeof header !== "string") {
    return {};
  }
  const match = /^Bearer +(\S+)$/i.exec(header);
  if (!match || !SESSION_TOKEN_PATTERN.test(match[1]!)) {
    return {};
  }
  return { Authorization: `Bearer ${match[1]}` };
}
