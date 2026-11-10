import { createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { deepFreeze, type AuthContext } from "./context.js";
import type { Auth, AuthFailureInfo } from "./session.js";
import { buildAuth, raceWithAbort, resolveClockSkewSeconds, resolveRealm, type VerifyResult } from "./middleware.js";

export type JwtAlgorithm = "RS256" | "ES256" | "HS256";

export interface JwtVerifierOptions {
  /** JWKS endpoint. Must be https unless allowInsecureJwksUri is set. Required when RS256 or ES256 is allowed. */
  jwksUri?: string;
  /** Allow an http jwksUri. Intended for local development and tests only. Default: false. */
  allowInsecureJwksUri?: boolean;
  /** Accepted "iss" value(s). */
  issuer: string | string[];
  /** Accepted "aud" value(s). The token must contain at least one. */
  audience: string | string[];
  /** Allowed "alg" values. Default: ["RS256", "ES256"]. HS256 must be listed explicitly. */
  algorithms?: JwtAlgorithm[];
  /** Shared secret for HS256, at least 32 bytes. Required if and only if HS256 is allowed. */
  hmacSecret?: string | Uint8Array;
  /** Claims that must be present (not null or undefined) in addition to sub and exp. */
  requiredClaims?: string[];
  /** Tolerated clock difference when checking exp and nbf. Default: 5. */
  clockSkewSeconds?: number;
  /** Abort budget for one JWKS fetch. Default: 1000. */
  jwksTimeoutMs?: number;
  /** How long fetched keys are reused before refetching. Default: 600000 (10 minutes). */
  jwksCacheTtlMs?: number;
  /** Minimum time between refetches triggered by an unknown kid. Default: 30000. */
  jwksRefetchCooldownMs?: number;
  /** Sent in WWW-Authenticate on 401. Default: "api". */
  realm?: string;
  /** Pass CORS preflight (OPTIONS) through unauthenticated. Default: false. */
  skipPreflight?: boolean;
  /** Invoked on every denial, after the response is decided. Must never throw. */
  onAuthFailure?: (info: AuthFailureInfo) => void;
  /** Fetch implementation used for the JWKS. Default: global fetch. */
  fetch?: typeof fetch;
}

const SUPPORTED_ALGORITHMS: readonly JwtAlgorithm[] = ["RS256", "ES256", "HS256"];
const JWT_PATTERN = /^(?=.{1,8192}$)[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MIN_HMAC_SECRET_BYTES = 32;
const MIN_RSA_MODULUS_BITS = 2048;

interface JwksKey {
  key: KeyObject;
  kty: string;
  crv?: string;
  alg?: string;
  use?: string;
}

type KeyLookup = { ok: true; key: JwksKey } | { ok: false; reason: "unknown" | "store_error" };

/**
 * Creates middleware that verifies stateless JWT bearer tokens.
 * Produces the same req.auth shape and 401/403/503 responses as createAuth.
 */
export function createJwtVerifier(options: JwtVerifierOptions): Auth {
  const realm = resolveRealm(options.realm);
  const clockSkewSeconds = resolveClockSkewSeconds(options.clockSkewSeconds);
  const skewMs = clockSkewSeconds * 1000;
  const issuers = resolveStringList(options.issuer, "issuer");
  const audiences = resolveStringList(options.audience, "audience");
  const algorithms = resolveAlgorithms(options.algorithms);
  const asymmetric = algorithms.some((alg) => alg !== "HS256");
  const hmacSecret = resolveHmacSecret(options.hmacSecret, algorithms.includes("HS256"));
  const requiredClaims = resolveRequiredClaims(options.requiredClaims);
  const timeoutMs = resolvePositiveInteger(options.jwksTimeoutMs, 1000, "jwksTimeoutMs");
  const cacheTtlMs = resolvePositiveInteger(options.jwksCacheTtlMs, 600_000, "jwksCacheTtlMs");
  const cooldownMs = resolveNonNegativeInteger(options.jwksRefetchCooldownMs, 30_000, "jwksRefetchCooldownMs");
  const jwksUri = asymmetric ? resolveJwksUri(options.jwksUri, options.allowInsecureJwksUri ?? false) : undefined;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (asymmetric && typeof fetchImpl !== "function") {
    throw new TypeError("fetch must be a function");
  }

  let cache: { keys: Map<string, JwksKey>; fetchedAt: number } | undefined;
  let inFlight: Promise<boolean> | undefined;

  /** Resolves true when the cache was refreshed, false on any fetch failure. Concurrent calls share one fetch. */
  function refresh(): Promise<boolean> {
    inFlight ??= fetchJwks().finally(() => {
      inFlight = undefined;
    });
    return inFlight;
  }

  async function fetchJwks(): Promise<boolean> {
    const signal = AbortSignal.timeout(timeoutMs);
    try {
      const body = await raceWithAbort(
        (async () => {
          const response = await fetchImpl(jwksUri!, { signal, headers: { accept: "application/json" } });
          if (response.status !== 200) throw new Error("JWKS fetch failed");
          return (await response.json()) as unknown;
        })(),
        signal,
      );
      cache = { keys: parseJwks(body), fetchedAt: Date.now() };
      return true;
    } catch {
      return false;
    }
  }

  async function findKey(kid: string): Promise<KeyLookup> {
    if (!cache || Date.now() - cache.fetchedAt >= cacheTtlMs) {
      if (!(await refresh())) return { ok: false, reason: "store_error" };
    }
    let key = cache!.keys.get(kid);
    if (key) return { ok: true, key };
    // Unknown kid may mean the issuer rotated keys. Refetch, but rate-limit so random kids cannot hammer the JWKS.
    if (Date.now() - cache!.fetchedAt < cooldownMs) return { ok: false, reason: "unknown" };
    if (!(await refresh())) return { ok: false, reason: "store_error" };
    key = cache!.keys.get(kid);
    return key ? { ok: true, key } : { ok: false, reason: "unknown" };
  }

  async function verify(token: string): Promise<VerifyResult> {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".") as [string, string, string];
    const header = decodeJson(encodedHeader);
    const payload = decodeJson(encodedPayload);
    const signature = decodeBase64Url(encodedSignature);
    if (header === null || payload === null || signature === null) {
      return { ok: false, reason: "malformed" };
    }

    const alg = header.alg;
    if (typeof alg !== "string" || !(algorithms as readonly string[]).includes(alg)) {
      return { ok: false, reason: "unknown" };
    }
    // No critical header extensions are supported, so any "crit" makes the token unusable (RFC 7515 section 4.1.11).
    if (header.crit !== undefined) return { ok: false, reason: "unknown" };

    const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii");
    if (alg === "HS256") {
      if (!verifyHmac(signingInput, signature, hmacSecret!)) return { ok: false, reason: "unknown" };
    } else {
      const kid = header.kid;
      if (typeof kid !== "string" || kid === "") return { ok: false, reason: "unknown" };
      const found = await findKey(kid);
      if (!found.ok) return found;
      if (!keyMatchesAlgorithm(found.key, alg as JwtAlgorithm)) return { ok: false, reason: "unknown" };
      if (!verifyAsymmetric(alg as JwtAlgorithm, signingInput, signature, found.key.key)) {
        return { ok: false, reason: "unknown" };
      }
    }

    return checkClaims(payload);
  }

  function checkClaims(payload: Record<string, unknown>): VerifyResult {
    const now = Date.now();
    const { sub, exp, nbf, iss, aud, sid, tenant_id: tenantId } = payload;
    if (typeof sub !== "string" || sub === "") return { ok: false, reason: "unknown" };
    if (typeof exp !== "number" || !Number.isFinite(exp)) return { ok: false, reason: "unknown" };
    if (typeof iss !== "string" || !issuers.includes(iss)) return { ok: false, reason: "unknown" };
    const tokenAudiences = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud : [];
    if (!tokenAudiences.some((a) => typeof a === "string" && audiences.includes(a))) {
      return { ok: false, reason: "unknown" };
    }
    if (nbf !== undefined) {
      if (typeof nbf !== "number" || !Number.isFinite(nbf)) return { ok: false, reason: "unknown" };
      if (now + skewMs < nbf * 1000) return { ok: false, reason: "unknown" };
    }
    if (requiredClaims.some((claim) => payload[claim] === undefined || payload[claim] === null)) {
      return { ok: false, reason: "unknown" };
    }
    if (sid !== undefined && typeof sid !== "string") return { ok: false, reason: "unknown" };
    if (tenantId !== undefined && typeof tenantId !== "string") return { ok: false, reason: "unknown" };
    const scopes = readScopes(payload);
    if (scopes === null) return { ok: false, reason: "unknown" };
    if (now > exp * 1000 + skewMs) return { ok: false, reason: "expired" };

    const context: AuthContext = {
      kind: "session",
      subjectId: sub,
      ...(sid !== undefined ? { sessionId: sid } : {}),
      scopes,
      metadata: tenantId !== undefined ? { tenantId } : {},
    };
    return { ok: true, context: deepFreeze(context) };
  }

  return buildAuth({
    realm,
    skipPreflight: options.skipPreflight ?? false,
    onAuthFailure: options.onAuthFailure,
    tokenPattern: JWT_PATTERN,
    verify,
  });
}

/** scp (array or space-separated string) wins over scope. Returns null if the claim has the wrong type. */
function readScopes(payload: Record<string, unknown>): string[] | null {
  const raw = payload.scp !== undefined ? payload.scp : payload.scope;
  if (raw === undefined) return [];
  if (typeof raw === "string") return raw.split(" ").filter((s) => s !== "");
  if (Array.isArray(raw) && raw.every((s) => typeof s === "string")) return raw.filter((s) => s !== "");
  return null;
}

function parseJwks(body: unknown): Map<string, JwksKey> {
  if (typeof body !== "object" || body === null || !Array.isArray((body as { keys?: unknown }).keys)) {
    throw new Error("invalid JWKS");
  }
  const keys = new Map<string, JwksKey>();
  for (const jwk of (body as { keys: unknown[] }).keys) {
    if (typeof jwk !== "object" || jwk === null) continue;
    const { kid, kty, crv, alg, use } = jwk as Record<string, unknown>;
    // Only asymmetric keys are accepted from the JWKS. Symmetric keys there would enable alg confusion.
    if (typeof kid !== "string" || (kty !== "RSA" && kty !== "EC")) continue;
    try {
      const key = createPublicKey({ key: jwk as never, format: "jwk" });
      keys.set(kid, {
        key,
        kty,
        ...(typeof crv === "string" ? { crv } : {}),
        ...(typeof alg === "string" ? { alg } : {}),
        ...(typeof use === "string" ? { use } : {}),
      });
    } catch {
      // Skip keys Node cannot import. Tokens that reference them fail as unknown.
    }
  }
  return keys;
}

function keyMatchesAlgorithm(jwk: JwksKey, alg: JwtAlgorithm): boolean {
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (alg === "RS256") {
    const bits = jwk.key.asymmetricKeyDetails?.modulusLength ?? 0;
    return jwk.kty === "RSA" && bits >= MIN_RSA_MODULUS_BITS;
  }
  if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256";
  return false;
}

function verifyAsymmetric(alg: JwtAlgorithm, data: Buffer, signature: Buffer, key: KeyObject): boolean {
  try {
    if (alg === "RS256") return cryptoVerify("sha256", data, key, signature);
    if (alg === "ES256") {
      if (signature.length !== 64) return false;
      return cryptoVerify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
    return false;
  } catch {
    return false;
  }
}

function verifyHmac(data: Buffer, signature: Buffer, secret: Buffer): boolean {
  const expected = createHmac("sha256", secret).update(data).digest();
  return signature.length === expected.length && timingSafeEqual(signature, expected);
}

function decodeBase64Url(segment: string): Buffer | null {
  if (segment.length % 4 === 1) return null;
  return Buffer.from(segment, "base64url");
}

function decodeJson(segment: string): Record<string, unknown> | null {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function resolveStringList(value: string | string[] | undefined, name: string): string[] {
  const list = Array.isArray(value) ? [...value] : value === undefined ? [] : [value];
  if (list.length === 0 || !list.every((v) => typeof v === "string" && v !== "")) {
    throw new TypeError(`${name} must be a non-empty string or array of non-empty strings`);
  }
  return list;
}

function resolveAlgorithms(value: JwtAlgorithm[] | undefined): JwtAlgorithm[] {
  const list = value === undefined ? ["RS256", "ES256"] : [...value];
  if (!Array.isArray(value) && value !== undefined) throw new TypeError("algorithms must be an array");
  if (list.length === 0 || !list.every((alg) => (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg))) {
    throw new TypeError(`algorithms must be a non-empty subset of ${SUPPORTED_ALGORITHMS.join(", ")}`);
  }
  return list as JwtAlgorithm[];
}

function resolveHmacSecret(value: string | Uint8Array | undefined, required: boolean): Buffer | undefined {
  if (!required) {
    if (value !== undefined) throw new TypeError("hmacSecret is only allowed when algorithms includes HS256");
    return undefined;
  }
  const secret =
    typeof value === "string" ? Buffer.from(value, "utf8") : value instanceof Uint8Array ? Buffer.from(value) : null;
  if (secret === null || secret.length < MIN_HMAC_SECRET_BYTES) {
    throw new TypeError(`hmacSecret must be at least ${MIN_HMAC_SECRET_BYTES} bytes when HS256 is allowed`);
  }
  return secret;
}

function resolveRequiredClaims(value: string[] | undefined): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((c) => typeof c === "string" && c !== "")) {
    throw new TypeError("requiredClaims must be an array of non-empty strings");
  }
  return [...value];
}

function resolveJwksUri(value: string | undefined, allowInsecure: boolean): string {
  let url: URL;
  try {
    url = new URL(value ?? "");
  } catch {
    throw new TypeError("jwksUri must be a valid URL when RS256 or ES256 is allowed");
  }
  if (url.protocol !== "https:" && !(allowInsecure && url.protocol === "http:")) {
    throw new TypeError("jwksUri must use https");
  }
  return url.href;
}

function resolvePositiveInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) throw new TypeError(`${name} must be a positive integer`);
  return resolved;
}

function resolveNonNegativeInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 0) throw new TypeError(`${name} must be a non-negative integer`);
  return resolved;
}
