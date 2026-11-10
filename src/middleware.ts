import type { NextFunction, Request, RequestHandler, Response } from "express";
import { denialFor, type Denial, type DenialReason } from "./errors.js";
import type { AuthContext } from "./context.js";
import type { Auth, AuthFailureInfo } from "./session.js";

/** Internal: shared middleware plumbing for the opaque and JWT verifiers. Not exported publicly. */

const REALM_PATTERN = /^[\x20-\x7e]*$/;
const REALM_FORBIDDEN = /["\\]/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export type VerifyResult =
  | { ok: true; context: AuthContext }
  | { ok: false; reason: "malformed" | "unknown" | "expired" | "store_error" };

export interface AuthCore {
  realm: string;
  skipPreflight: boolean;
  onAuthFailure: ((info: AuthFailureInfo) => void) | undefined;
  /** Syntactic check applied to the bearer credential before verify. */
  tokenPattern: RegExp;
  /** Must not throw; a rejection is treated as store_error. */
  verify(token: string): Promise<VerifyResult>;
}

export function resolveRealm(realm: string | undefined): string {
  const value = realm ?? "api";
  if (!REALM_PATTERN.test(value) || REALM_FORBIDDEN.test(value)) {
    throw new TypeError("realm must be printable ASCII without quotes or backslashes");
  }
  return value;
}

export function resolveClockSkewSeconds(clockSkewSeconds: number | undefined): number {
  const value = clockSkewSeconds ?? 5;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError("clockSkewSeconds must be a finite number >= 0");
  }
  return value;
}

export function buildAuth(core: AuthCore): Auth {
  const { realm, skipPreflight, onAuthFailure, tokenPattern, verify } = core;

  function notify(req: Request, reason: DenialReason): void {
    if (!onAuthFailure) return;
    try {
      const raw = req.get("x-request-id");
      const requestId = raw && REQUEST_ID_PATTERN.test(raw) ? raw : undefined;
      onAuthFailure({ reason, ...(requestId ? { requestId } : {}) });
    } catch {
      // Observer errors must never affect the response.
    }
  }

  function deny(req: Request, res: Response, _next: NextFunction, denial: Denial): void {
    if (res.headersSent) {
      // Cannot respond. Do not call next(): that would pass the request through unauthenticated.
      notify(req, denial.reason);
      res.destroy();
      return;
    }
    res.setHeader("Cache-Control", "no-store");
    if (denial.challenge) {
      res.setHeader("WWW-Authenticate", denial.challenge);
    }
    res.status(denial.status).json(denial.body);
    notify(req, denial.reason);
  }

  /** Returns the token, null if the header is absent, or { malformed } if the header is invalid. */
  function extractToken(header: string | undefined): { token: string } | { malformed: true } | null {
    if (header === undefined) return null;
    if (/[\r\n\0]/.test(header)) return { malformed: true };
    const match = /^Bearer +(.+)$/i.exec(header);
    if (!match) return { malformed: true };
    const token = match[1]!;
    if (!tokenPattern.test(token)) return { malformed: true };
    return { token };
  }

  async function authenticate(req: Request, res: Response, next: NextFunction, optional: boolean): Promise<void> {
    if (skipPreflight && req.method === "OPTIONS") {
      next();
      return;
    }
    const header = req.headers.authorization;
    if (header === undefined && optional) {
      next();
      return;
    }
    const parsed = extractToken(header);
    if (parsed === null) {
      deny(req, res, next, denialFor("missing", realm));
      return;
    }
    if ("malformed" in parsed) {
      deny(req, res, next, denialFor("malformed", realm));
      return;
    }
    const result = await verify(parsed.token);
    if (!result.ok) {
      deny(req, res, next, denialFor(result.reason, realm));
      return;
    }
    req.auth = result.context;
    next();
  }

  const handle = (optional: boolean): RequestHandler => (req, res, next) => {
    authenticate(req, res, next, optional).catch(() => {
      // Unreachable by design: authenticate handles its own failures. Fail closed if it ever happens.
      if (!res.headersSent) {
        deny(req, res, next, denialFor("store_error", realm));
      }
    });
  };

  return {
    requireAuth: handle(false),
    optionalAuth: handle(true),
    requireScope(scope) {
      const required = Array.isArray(scope) ? [...scope] : [scope];
      if (required.length === 0 || !required.every((s) => typeof s === "string" && s !== "")) {
        // An empty list would allow every authenticated request.
        throw new TypeError("requireScope needs at least one non-empty scope string");
      }
      return (req, res, next) => {
        if (!req.auth) {
          deny(req, res, next, denialFor("missing", realm));
          return;
        }
        const granted = new Set(req.auth.scopes);
        if (!required.every((s) => granted.has(s))) {
          deny(req, res, next, denialFor("insufficient_scope", realm));
          return;
        }
        next();
      };
    },
  };
}

/**
 * Rejects when the abort signal fires, even if the underlying operation ignores the signal.
 * Keeps the 503 inside the timeout budget.
 */
export function raceWithAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error("aborted"));
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}
