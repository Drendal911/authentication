import type { NextFunction, Request, RequestHandler, Response } from "express";
import { denialFor, type Denial, type DenialReason } from "./errors.js";
import { deepFreeze, type AuthContext } from "./context.js";
import type { SessionRecord, SessionStore } from "./store.js";
import { hashSessionToken, SESSION_TOKEN_PATTERN } from "./tokens.js";

export interface AuthOptions {
  sessions: SessionStore;
  /** Sent in WWW-Authenticate on 401. Default: "api". */
  realm?: string;
  /** Tolerated clock difference when checking expiresAt. Default: 5. */
  clockSkewSeconds?: number;
  /** Abort budget for one store lookup. Default: 1000. */
  storeTimeoutMs?: number;
  /** Pass CORS preflight (OPTIONS) through unauthenticated. Default: false. */
  skipPreflight?: boolean;
  /** Invoked on every denial, after the response is decided. Must never throw. */
  onAuthFailure?: (info: AuthFailureInfo) => void;
}

export interface AuthFailureInfo {
  reason: DenialReason;
  /** Never include the token or any part of it. */
  requestId?: string;
}

export interface Auth {
  /** 401 without a valid token. Populates req.auth. */
  requireAuth: RequestHandler;
  /** 401 only if a malformed or invalid token is present; otherwise next(). */
  optionalAuth: RequestHandler;
  /**
   * 403 if req.auth lacks the scope. Mount after requireAuth.
   * An array means ALL listed scopes are required (AND).
   */
  requireScope(scope: string | string[]): RequestHandler;
}

const REALM_PATTERN = /^[\x20-\x7e]*$/;
const REALM_FORBIDDEN = /["\\]/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export function createAuth(options: AuthOptions): Auth {
  const realm = options.realm ?? "api";
  if (!REALM_PATTERN.test(realm) || REALM_FORBIDDEN.test(realm)) {
    throw new TypeError("realm must be printable ASCII without quotes or backslashes");
  }
  if (typeof options.sessions?.findByHash !== "function") {
    throw new TypeError("sessions must implement findByHash");
  }
  const clockSkewSeconds = options.clockSkewSeconds ?? 5;
  if (typeof clockSkewSeconds !== "number" || !Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new TypeError("clockSkewSeconds must be a finite number >= 0");
  }
  const timeoutMs = options.storeTimeoutMs ?? 1000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("storeTimeoutMs must be a positive integer");
  }
  const skewMs = clockSkewSeconds * 1000;
  const skipPreflight = options.skipPreflight ?? false;
  const sessions = options.sessions;
  const onAuthFailure = options.onAuthFailure;

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

  function deny(req: Request, res: Response, next: NextFunction, denial: Denial): void {
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
    if (!SESSION_TOKEN_PATTERN.test(token)) return { malformed: true };
    return { token };
  }

  type Lookup =
    | { ok: true; record: SessionRecord }
    | { ok: false; reason: "unknown" | "expired" | "store_error" };

  async function lookup(token: string): Promise<Lookup> {
    const hash = hashSessionToken(token);
    const signal = AbortSignal.timeout(timeoutMs);
    let record: SessionRecord | null;
    try {
      record = await raceWithAbort(
        new Promise<SessionRecord | null>((resolve) => resolve(sessions.findByHash(hash, { signal }))),
        signal,
      );
    } catch {
      return { ok: false, reason: "store_error" };
    }
    if (record === null || record === undefined) {
      return { ok: false, reason: "unknown" };
    }
    if (!isValidRecord(record)) {
      return { ok: false, reason: "store_error" };
    }
    const expiresMs = toEpochMs(record.expiresAt);
    if (expiresMs === null) {
      return { ok: false, reason: "store_error" };
    }
    if (Date.now() > expiresMs + skewMs) {
      return { ok: false, reason: "expired" };
    }
    return { ok: true, record };
  }

  function buildContext(record: SessionRecord): AuthContext | null {
    let metadata: Record<string, unknown>;
    try {
      metadata = structuredClone(record.metadata ?? {});
    } catch {
      return null;
    }
    const context: AuthContext = {
      kind: "session",
      subjectId: record.subjectId,
      ...(record.sessionId != null ? { sessionId: record.sessionId } : {}),
      scopes: [...(record.scopes ?? [])],
      metadata,
    };
    return deepFreeze(context);
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
    const result = await lookup(parsed.token);
    if (!result.ok) {
      deny(req, res, next, denialFor(result.reason, realm));
      return;
    }
    const context = buildContext(result.record);
    if (context === null) {
      deny(req, res, next, denialFor("store_error", realm));
      return;
    }
    req.auth = context;
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

/** Optional fields may be null (common for nullable DB columns) and are treated as absent. */
function isValidRecord(record: unknown): record is SessionRecord {
  if (typeof record !== "object" || record === null) return false;
  const r = record as Record<string, unknown>;
  if (typeof r.subjectId !== "string" || r.subjectId === "") return false;
  if (r.sessionId != null && typeof r.sessionId !== "string") return false;
  if (r.scopes != null && !(Array.isArray(r.scopes) && r.scopes.every((s) => typeof s === "string"))) return false;
  if (r.metadata != null && (typeof r.metadata !== "object" || Array.isArray(r.metadata))) return false;
  return true;
}

function toEpochMs(expiresAt: unknown): number | null {
  if (expiresAt instanceof Date) {
    const ms = expiresAt.getTime();
    return Number.isFinite(ms) ? ms : null;
  }
  if (typeof expiresAt === "number" && Number.isFinite(expiresAt)) {
    return expiresAt;
  }
  return null;
}

/**
 * Rejects when the abort signal fires, even if the store ignores the signal.
 * Keeps the 503 inside the timeout budget.
 */
function raceWithAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
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
