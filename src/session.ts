import type { RequestHandler } from "express";
import type { DenialReason } from "./errors.js";
import { deepFreeze, type AuthContext } from "./context.js";
import type { SessionRecord, SessionStore } from "./store.js";
import { hashSessionToken, SESSION_TOKEN_PATTERN } from "./tokens.js";
import { buildAuth, raceWithAbort, resolveClockSkewSeconds, resolveRealm, type VerifyResult } from "./middleware.js";

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

export function createAuth(options: AuthOptions): Auth {
  const realm = resolveRealm(options.realm);
  if (typeof options.sessions?.findByHash !== "function") {
    throw new TypeError("sessions must implement findByHash");
  }
  const clockSkewSeconds = resolveClockSkewSeconds(options.clockSkewSeconds);
  const timeoutMs = options.storeTimeoutMs ?? 1000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("storeTimeoutMs must be a positive integer");
  }
  const skewMs = clockSkewSeconds * 1000;
  const sessions = options.sessions;

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

  async function verify(token: string): Promise<VerifyResult> {
    const result = await lookup(token);
    if (!result.ok) return result;
    const context = buildContext(result.record);
    if (context === null) return { ok: false, reason: "store_error" };
    return { ok: true, context };
  }

  return buildAuth({
    realm,
    skipPreflight: options.skipPreflight ?? false,
    onAuthFailure: options.onAuthFailure,
    tokenPattern: SESSION_TOKEN_PATTERN,
    verify,
  });
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
