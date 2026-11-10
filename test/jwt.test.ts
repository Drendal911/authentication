import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHmac, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createJwtVerifier, type JwtVerifierOptions } from "../src/jwt.js";
import type { AuthFailureInfo } from "../src/session.js";

// Test-only keys, generated fresh for each run. Never use real keys here.
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsaOther = generateKeyPairSync("rsa", { modulusLength: 2048 });
const HMAC_SECRET = "test-only-hmac-secret-0123456789abcdef";

const ISSUER = "https://issuer.test";
const AUDIENCE = "api://test";
const JWKS_URI = "https://issuer.test/.well-known/jwks.json";

function jwk(key: KeyObject, kid: string, extra: Record<string, unknown> = {}) {
  return { ...key.export({ format: "jwk" }), kid, ...extra };
}

const JWKS = { keys: [jwk(rsa.publicKey, "rsa-1"), jwk(ec.publicKey, "ec-1")] };

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

function claims(overrides: Record<string, unknown> = {}) {
  return { iss: ISSUER, aud: AUDIENCE, sub: "user-1", exp: now() + 300, ...overrides };
}

function signJwt(
  payload: Record<string, unknown>,
  opts: { alg?: string; kid?: string | undefined; key?: KeyObject; header?: Record<string, unknown> } = {},
): string {
  const alg = opts.alg ?? "RS256";
  const header: Record<string, unknown> = { alg, typ: "JWT", ...opts.header };
  if ("kid" in opts) {
    if (opts.kid !== undefined) header.kid = opts.kid;
  } else if (alg === "RS256") header.kid = "rsa-1";
  else if (alg === "ES256") header.kid = "ec-1";
  const input = `${b64(header)}.${b64(payload)}`;
  let signature: Buffer;
  if (alg === "RS256") signature = sign("sha256", Buffer.from(input), opts.key ?? rsa.privateKey);
  else if (alg === "ES256")
    signature = sign("sha256", Buffer.from(input), { key: opts.key ?? ec.privateKey, dsaEncoding: "ieee-p1363" });
  else if (alg === "HS256") signature = createHmac("sha256", HMAC_SECRET).update(input).digest();
  else signature = Buffer.alloc(0);
  return `${input}.${signature.toString("base64url")}`;
}

function mockFetch(body: unknown = JWKS, status = 200) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  );
}

function baseOptions(overrides: Partial<JwtVerifierOptions> = {}): JwtVerifierOptions {
  return { jwksUri: JWKS_URI, issuer: ISSUER, audience: AUDIENCE, fetch: mockFetch() as typeof fetch, ...overrides };
}

function makeApp(options: JwtVerifierOptions) {
  const app = express();
  const auth = createJwtVerifier(options);
  app.get("/me", auth.requireAuth, (req, res) => {
    res.json(req.auth);
  });
  app.get("/opt", auth.optionalAuth, (req, res) => {
    res.json({ present: req.auth !== undefined });
  });
  app.get("/admin", auth.requireAuth, auth.requireScope("admin"), (_req, res) => {
    res.json({ ok: true });
  });
  return app;
}

const servers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((close) => close()));
});

async function serve(options: JwtVerifierOptions): Promise<string> {
  const server: Server = await new Promise((resolve) => {
    const s = makeApp(options).listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const get = (url: string, token?: string) =>
  fetch(url, token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } });

describe("createJwtVerifier", () => {
  it("accepts RS256 and maps claims to req.auth", async () => {
    const url = await serve(baseOptions());
    const token = signJwt(claims({ sid: "s-1", scp: ["read", "write"], tenant_id: "t-1" }));
    const res = await get(`${url}/me`, token);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      kind: "session",
      subjectId: "user-1",
      sessionId: "s-1",
      scopes: ["read", "write"],
      metadata: { tenantId: "t-1" },
    });
  });

  it("accepts ES256", async () => {
    const url = await serve(baseOptions());
    const res = await get(`${url}/me`, signJwt(claims(), { alg: "ES256" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ subjectId: "user-1", scopes: [], metadata: {} });
  });

  it("reads scp as a space-separated string and falls back to scope", async () => {
    const url = await serve(baseOptions());
    const a = await get(`${url}/me`, signJwt(claims({ scp: "a b" })));
    expect(((await a.json()) as { scopes: string[] }).scopes).toEqual(["a", "b"]);
    const b = await get(`${url}/me`, signJwt(claims({ scope: "x  y" })));
    expect(((await b.json()) as { scopes: string[] }).scopes).toEqual(["x", "y"]);
  });

  it("rejects alg none and HS256 when not configured", async () => {
    const url = await serve(baseOptions());
    const none = `${b64({ alg: "none", typ: "JWT" })}.${b64(claims())}.AA`;
    expect((await get(`${url}/me`, none)).status).toBe(401);
    const hs = signJwt(claims(), { alg: "HS256" });
    const res = await get(`${url}/me`, hs);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("accepts HS256 when explicitly configured", async () => {
    const fetchSpy = mockFetch();
    const url = await serve(
      baseOptions({ algorithms: ["HS256"], hmacSecret: HMAC_SECRET, jwksUri: undefined, fetch: fetchSpy as typeof fetch }),
    );
    expect((await get(`${url}/me`, signJwt(claims(), { alg: "HS256" }))).status).toBe(200);
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a bad signature, an unknown kid, and a missing kid", async () => {
    const url = await serve(baseOptions({ jwksRefetchCooldownMs: 0 }));
    expect((await get(`${url}/me`, signJwt(claims(), { key: rsaOther.privateKey }))).status).toBe(401);
    expect((await get(`${url}/me`, signJwt(claims(), { kid: "nope" }))).status).toBe(401);
    expect((await get(`${url}/me`, signJwt(claims(), { kid: undefined }))).status).toBe(401);
  });

  it("rejects a key whose type does not match the alg", async () => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/me`, signJwt(claims(), { alg: "ES256", kid: "rsa-1" }))).status).toBe(401);
  });

  it("rejects tokens with crit headers", async () => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/me`, signJwt(claims(), { header: { crit: ["x"] } }))).status).toBe(401);
  });

  it("rejects malformed tokens", async () => {
    const onAuthFailure = vi.fn<(info: AuthFailureInfo) => void>();
    const url = await serve(baseOptions({ onAuthFailure }));
    expect((await get(`${url}/me`, "not-a-jwt")).status).toBe(401);
    expect((await get(`${url}/me`, `${b64("str")}.${b64(claims())}.AA`)).status).toBe(401);
    expect((await get(`${url}/me`, "e30.bm90anNvbg.AA")).status).toBe(401);
    expect(onAuthFailure.mock.calls.every(([info]) => info.reason === "malformed")).toBe(true);
    expect(onAuthFailure).toHaveBeenCalledTimes(3);
  });

  it.each([
    ["wrong issuer", { iss: "https://evil.test" }],
    ["wrong audience", { aud: "api://other" }],
    ["nbf in the future", { nbf: now() + 120 }],
    ["missing sub", { sub: undefined }],
    ["missing exp", { exp: undefined }],
    ["non-string sid", { sid: 5 }],
    ["bad scp type", { scp: [1] }],
  ])("rejects %s", async (_name, override) => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/me`, signJwt(claims(override)))).status).toBe(401);
  });

  it("accepts an audience array containing a configured audience", async () => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/me`, signJwt(claims({ aud: ["other", AUDIENCE] })))).status).toBe(200);
  });

  it("honors clock skew for exp and nbf", async () => {
    const url = await serve(baseOptions({ clockSkewSeconds: 30 }));
    expect((await get(`${url}/me`, signJwt(claims({ exp: now() - 10 })))).status).toBe(200);
    expect((await get(`${url}/me`, signJwt(claims({ nbf: now() + 10 })))).status).toBe(200);
  });

  it("reports expired tokens", async () => {
    const onAuthFailure = vi.fn<(info: AuthFailureInfo) => void>();
    const url = await serve(baseOptions({ onAuthFailure }));
    const res = await get(`${url}/me`, signJwt(claims({ exp: now() - 60 })));
    expect(res.status).toBe(401);
    expect(onAuthFailure.mock.calls[0]![0].reason).toBe("expired");
  });

  it("enforces requiredClaims", async () => {
    const url = await serve(baseOptions({ requiredClaims: ["tenant_id"] }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(401);
    expect((await get(`${url}/me`, signJwt(claims({ tenant_id: "t" })))).status).toBe(200);
  });

  it("returns 403 from requireScope when the scope is missing", async () => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/admin`, signJwt(claims({ scp: "read" })))).status).toBe(403);
    expect((await get(`${url}/admin`, signJwt(claims({ scp: "admin" })))).status).toBe(200);
  });

  it("optionalAuth passes through with no header but rejects a bad token", async () => {
    const url = await serve(baseOptions());
    expect(await (await get(`${url}/opt`)).json()).toEqual({ present: false });
    expect((await get(`${url}/opt`, "bad")).status).toBe(401);
    expect(await (await get(`${url}/opt`, signJwt(claims()))).json()).toEqual({ present: true });
  });

  it("caches the JWKS and coalesces concurrent fetches", async () => {
    const fetchSpy = mockFetch();
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch }));
    const results = await Promise.all(Array.from({ length: 5 }, () => get(`${url}/me`, signJwt(claims()))));
    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect((await get(`${url}/me`, signJwt(claims(), { alg: "ES256" }))).status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0]![0])).toBe(JWKS_URI);
  });

  it("refetches once on an unknown kid to pick up rotated keys", async () => {
    let body: unknown = { keys: [jwk(rsa.publicKey, "rsa-1")] };
    const fetchSpy = vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch, jwksRefetchCooldownMs: 0 }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
    body = { keys: [jwk(rsa.publicKey, "rsa-1"), jwk(rsaOther.publicKey, "rsa-2")] };
    expect((await get(`${url}/me`, signJwt(claims(), { kid: "rsa-2", key: rsaOther.privateKey }))).status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("does not refetch for unknown kids within the cooldown", async () => {
    const fetchSpy = mockFetch();
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch, jwksRefetchCooldownMs: 60_000 }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
    for (const kid of ["a", "b", "c"]) {
      expect((await get(`${url}/me`, signJwt(claims(), { kid }))).status).toBe(401);
    }
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("refetches after the cache TTL expires", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const fetchSpy = mockFetch();
      const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch, jwksCacheTtlMs: 1000 }));
      expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
      vi.setSystemTime(Date.now() + 2000);
      expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("skips JWKS keys with a mismatched alg or a non-sig use", async () => {
    const body = { keys: [jwk(rsa.publicKey, "rsa-1", { alg: "RS512" }), jwk(ec.publicKey, "ec-1", { use: "enc" })] };
    const url = await serve(baseOptions({ fetch: mockFetch(body) as typeof fetch }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(401);
    expect((await get(`${url}/me`, signJwt(claims(), { alg: "ES256" }))).status).toBe(401);
  });

  it.each([
    ["a network error", vi.fn(async () => Promise.reject(new Error("boom")))],
    ["a non-200 status", mockFetch({ error: "x" }, 500)],
    ["invalid JSON", vi.fn(async () => new Response("not json", { status: 200 }))],
    ["a body without keys", mockFetch({ nope: true })],
  ])("returns 503 on %s from the JWKS", async (_name, fetchImpl) => {
    const onAuthFailure = vi.fn<(info: AuthFailureInfo) => void>();
    const url = await serve(baseOptions({ fetch: fetchImpl as typeof fetch, onAuthFailure }));
    const res = await get(`${url}/me`, signJwt(claims()));
    expect(res.status).toBe(503);
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect(onAuthFailure.mock.calls[0]![0].reason).toBe("store_error");
  });

  it("returns 503 when the JWKS fetch times out", async () => {
    const hang = vi.fn(() => new Promise<Response>(() => {}));
    const url = await serve(baseOptions({ fetch: hang as typeof fetch, jwksTimeoutMs: 50 }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(503);
  });

  it("does not cache a failed JWKS fetch", async () => {
    let fail = true;
    const fetchSpy = vi.fn(async () =>
      fail ? new Response("", { status: 500 }) : new Response(JSON.stringify(JWKS), { status: 200 }),
    );
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(503);
    fail = false;
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
  });

  it.each<[string, Partial<JwtVerifierOptions>]>([
    ["missing issuer", { issuer: undefined as unknown as string }],
    ["empty audience", { audience: [] }],
    ["http jwksUri", { jwksUri: "http://issuer.test/jwks" }],
    ["missing jwksUri", { jwksUri: undefined }],
    ["unsupported alg", { algorithms: ["none" as "RS256"] }],
    ["empty algorithms", { algorithms: [] }],
    ["HS256 without secret", { algorithms: ["HS256"] }],
    ["short HMAC secret", { algorithms: ["HS256"], hmacSecret: "short" }],
    ["secret without HS256", { hmacSecret: HMAC_SECRET }],
    ["bad timeout", { jwksTimeoutMs: 0 }],
    ["bad requiredClaims", { requiredClaims: [""] }],
    ["bad clock skew", { clockSkewSeconds: -1 }],
  ])("throws TypeError for %s", (_name, override) => {
    expect(() => createJwtVerifier(baseOptions(override))).toThrow(TypeError);
  });

  it("allows an http jwksUri only when explicitly opted in", () => {
    expect(() =>
      createJwtVerifier(baseOptions({ jwksUri: "http://127.0.0.1/jwks", allowInsecureJwksUri: true })),
    ).not.toThrow();
  });
});

describe("createJwtVerifier attack classes", () => {
  function hmacToken(header: Record<string, unknown>, payload: Record<string, unknown>, secret: string | Buffer) {
    const input = `${b64(header)}.${b64(payload)}`;
    return `${input}.${createHmac("sha256", secret).update(input).digest("base64url")}`;
  }

  it.each(["none", "None", "NONE", "nOnE"])("rejects alg %s with empty or junk signatures", async (alg) => {
    const fetchSpy = mockFetch();
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch }));
    const unsigned = `${b64({ alg, typ: "JWT" })}.${b64(claims())}`;
    for (const token of [`${unsigned}.`, `${unsigned}.AA`, `${b64({ alg, kid: "rsa-1" })}.${b64(claims())}.`]) {
      const res = await get(`${url}/me`, token);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain("invalid_token");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  describe("alg confusion (HS256 signed with the RSA public key)", () => {
    const pem = rsa.publicKey.export({ type: "spki", format: "pem" }) as string;
    const der = rsa.publicKey.export({ type: "spki", format: "der" });
    const jwkJson = JSON.stringify(jwk(rsa.publicKey, "rsa-1"));
    const secrets: Array<[string, string | Buffer]> = [
      ["PEM", pem],
      ["DER", der],
      ["JWK JSON", jwkJson],
    ];

    it.each(secrets)("rejects under the default algorithms (public key as %s)", async (_name, secret) => {
      const url = await serve(baseOptions());
      const res = await get(`${url}/me`, hmacToken({ alg: "HS256", typ: "JWT", kid: "rsa-1" }, claims(), secret));
      expect(res.status).toBe(401);
    });

    it.each(secrets)("rejects even when HS256 is enabled (public key as %s)", async (_name, secret) => {
      const url = await serve(baseOptions({ algorithms: ["RS256", "HS256"], hmacSecret: HMAC_SECRET }));
      const res = await get(`${url}/me`, hmacToken({ alg: "HS256", typ: "JWT", kid: "rsa-1" }, claims(), secret));
      expect(res.status).toBe(401);
      // Control: the configured secret still works, so the rejection is about the key, not HS256 itself.
      expect((await get(`${url}/me`, signJwt(claims(), { alg: "HS256" }))).status).toBe(200);
    });
  });

  it.each<[string, string, string, KeyObject]>([
    ["ES256 token against an RSA key", "ES256", "rsa-1", ec.privateKey],
    ["RS256 token against an EC key", "RS256", "ec-1", rsa.privateKey],
  ])("rejects key-type mismatch: %s", async (_name, alg, kid, key) => {
    const url = await serve(baseOptions());
    expect((await get(`${url}/me`, signJwt(claims(), { alg, kid, key }))).status).toBe(401);
  });

  it("rejects an RS256 token whose kid points at an RSA key below 2048 bits", async () => {
    const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
    const url = await serve(baseOptions({ fetch: mockFetch({ keys: [jwk(weak.publicKey, "weak")] }) as typeof fetch }));
    expect((await get(`${url}/me`, signJwt(claims(), { kid: "weak", key: weak.privateKey }))).status).toBe(401);
  });

  it("refetches the JWKS exactly once for an unknown kid, then returns 401", async () => {
    const fetchSpy = mockFetch();
    const onAuthFailure = vi.fn<(info: AuthFailureInfo) => void>();
    const url = await serve(baseOptions({ fetch: fetchSpy as typeof fetch, jwksRefetchCooldownMs: 0, onAuthFailure }));
    expect((await get(`${url}/me`, signJwt(claims()))).status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const res = await get(`${url}/me`, signJwt(claims(), { kid: "missing", key: rsaOther.privateKey }));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("invalid_token");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(onAuthFailure.mock.calls[0]![0].reason).toBe("unknown");
  });

  describe("exp/nbf boundaries and clock skew", () => {
    const T = 1_900_000_000; // fixed whole second

    async function statusAt(payload: Record<string, unknown>, clockSkewSeconds?: number) {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(T * 1000);
        const options = clockSkewSeconds === undefined ? baseOptions() : baseOptions({ clockSkewSeconds });
        const url = await serve(options);
        return (await get(`${url}/me`, signJwt(payload))).status;
      } finally {
        vi.useRealTimers();
      }
    }

    it.each<[string, Record<string, unknown>, number | undefined, number]>([
      ["exp = now - skew is accepted", { exp: T - 5 }, 5, 200],
      ["exp = now - skew - 1 is rejected", { exp: T - 6 }, 5, 401],
      ["nbf = now + skew is accepted", { nbf: T + 5, exp: T + 300 }, 5, 200],
      ["nbf = now + skew + 1 is rejected", { nbf: T + 6, exp: T + 300 }, 5, 401],
      ["default skew: exp = now - 5 is accepted", { exp: T - 5 }, undefined, 200],
      ["default skew: exp = now - 6 is rejected", { exp: T - 6 }, undefined, 401],
      ["zero skew: exp = now is accepted", { exp: T }, 0, 200],
      ["zero skew: exp = now - 1 is rejected", { exp: T - 1 }, 0, 401],
      ["zero skew: nbf = now is accepted", { nbf: T, exp: T + 300 }, 0, 200],
      ["zero skew: nbf = now + 1 is rejected", { nbf: T + 1, exp: T + 300 }, 0, 401],
      ["large skew: exp = now - 60 is accepted at skew 60", { exp: T - 60 }, 60, 200],
    ])("%s", async (_name, times, skew, expected) => {
      expect(await statusAt(claims(times), skew)).toBe(expected);
    });

    it("reports an expired token with reason expired", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(T * 1000);
        const onAuthFailure = vi.fn<(info: AuthFailureInfo) => void>();
        const url = await serve(baseOptions({ clockSkewSeconds: 5, onAuthFailure }));
        expect((await get(`${url}/me`, signJwt(claims({ exp: T - 6 })))).status).toBe(401);
        expect(onAuthFailure.mock.calls[0]![0].reason).toBe("expired");
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
