import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth, type AuthFailureInfo, type AuthOptions } from "../src/session.js";
import type { SessionRecord, SessionStore } from "../src/store.js";
import { createSessionToken, hashSessionToken } from "../src/tokens.js";
import type { AuthContext } from "../src/context.js";

const TOKEN = createSessionToken();
const FUTURE = () => new Date(Date.now() + 60_000);

function storeWith(records: Record<string, SessionRecord>): SessionStore & { findByHash: ReturnType<typeof vi.fn> } {
  return {
    findByHash: vi.fn(async (hash: string) => records[hash] ?? null),
  } as unknown as SessionStore & { findByHash: ReturnType<typeof vi.fn> };
}

function makeApp(
  options: Partial<AuthOptions> & { sessions: SessionStore },
  setup?: (app: express.Express, auth: ReturnType<typeof createAuth>) => void,
) {
  const app = express();
  const auth = createAuth({ ...options, sessions: options.sessions });
  app.get("/me", auth.requireAuth, (req, res) => {
    res.json({ subjectId: req.auth!.subjectId, scopes: req.auth!.scopes });
  });
  app.get("/opt", auth.optionalAuth, (req, res) => {
    res.json({ present: req.auth !== undefined });
  });
  app.options("/me", auth.requireAuth, (_req, res) => {
    res.json({ ok: true });
  });
  app.get("/admin", auth.requireAuth, auth.requireScope("admin"), (_req, res) => {
    res.json({ ok: true });
  });
  app.get("/both", auth.requireAuth, auth.requireScope(["a", "b"]), (_req, res) => {
    res.json({ ok: true });
  });
  app.get("/scope-no-auth", auth.requireScope("admin"), (_req, res) => {
    res.json({ ok: true });
  });
  setup?.(app, auth);
  return app;
}

async function serve(app: express.Express): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("session middleware", () => {
  let server: { url: string; close: () => Promise<void> };
  const sessions = storeWith({
    [hashSessionToken(TOKEN)]: {
      subjectId: "user-1",
      sessionId: "s-1",
      expiresAt: FUTURE(),
      scopes: ["admin", "user"],
      metadata: { tenant: { id: "t1" } },
    },
  });

  beforeAll(async () => {
    server = await serve(makeApp({ sessions }));
  });
  afterAll(async () => {
    await server.close();
  });

  const get = (path: string, headers: Record<string, string> = {}, method = "GET") =>
    fetch(server.url + path, { method, headers });

  it("allows a valid token and populates a frozen req.auth", async () => {
    let captured: AuthContext | undefined;
    const app = makeApp({ sessions }, (a, auth) => {
      a.get("/capture", auth.requireAuth, (req, res) => {
        captured = req.auth;
        res.json({});
      });
    });
    const s = await serve(app);
    try {
      const res = await fetch(s.url + "/capture", { headers: { authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(200);
      expect(captured).toBeDefined();
      expect(Object.isFrozen(captured)).toBe(true);
      expect(Object.isFrozen(captured!.scopes)).toBe(true);
      expect(Object.isFrozen(captured!.metadata)).toBe(true);
      expect(Object.isFrozen((captured!.metadata as { tenant: object }).tenant)).toBe(true);
      expect(captured!.subjectId).toBe("user-1");
    } finally {
      await s.close();
    }
  });

  it("returns 401 without WWW-Authenticate error= for a missing header", async () => {
    const res = await get("/me");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Bearer realm="api"');
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("returns 401 malformed with error=invalid_token for Basic scheme", async () => {
    const reasons: string[] = [];
    const app = makeApp({ sessions, onAuthFailure: (i) => reasons.push(i.reason) });
    const s = await serve(app);
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: "Basic dXNlcjpwYXNz" } });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe('Bearer realm="api", error="invalid_token"');
      expect(reasons).toEqual(["malformed"]);
    } finally {
      await s.close();
    }
  });

  it("never calls the store for malformed tokens", async () => {
    const spy = storeWith({});
    const s = await serve(makeApp({ sessions: spy }));
    try {
      const bad = [
        `${TOKEN.slice(0, 42)}\n`,
        `${TOKEN.slice(0, 42)}+`,
        `${TOKEN.slice(0, 42)}=`,
        TOKEN.slice(0, 42),
        `${TOKEN}A`,
        `${TOKEN.slice(0, 42)}\0`,
      ];
      for (const value of bad) {
        const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${value}` } }).catch(() => null);
        if (res) expect(res.status).toBe(401);
      }
      expect(spy.findByHash).not.toHaveBeenCalled();
    } finally {
      await s.close();
    }
  });

  it("returns 401 unknown for an unknown token", async () => {
    const reasons: string[] = [];
    const s = await serve(makeApp({ sessions, onAuthFailure: (i) => reasons.push(i.reason) }));
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${createSessionToken()}` } });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "unauthorized" });
      expect(reasons).toEqual(["unknown"]);
    } finally {
      await s.close();
    }
  });

  it("honors clockSkewSeconds for expiry", async () => {
    const token = createSessionToken();
    const store = storeWith({
      [hashSessionToken(token)]: { subjectId: "u", expiresAt: new Date(Date.now() - 1000) },
    });
    const strict = await serve(makeApp({ sessions: store, clockSkewSeconds: 0 }));
    const lenient = await serve(makeApp({ sessions: store, clockSkewSeconds: 5 }));
    try {
      const expired = await fetch(strict.url + "/me", { headers: { authorization: `Bearer ${token}` } });
      expect(expired.status).toBe(401);

      const token3 = createSessionToken();
      const store3 = storeWith({
        [hashSessionToken(token3)]: { subjectId: "u", expiresAt: Date.now() - 3000 },
      });
      const within = await serve(makeApp({ sessions: store3, clockSkewSeconds: 5 }));
      try {
        const ok = await fetch(within.url + "/me", { headers: { authorization: `Bearer ${token3}` } });
        expect(ok.status).toBe(200);
      } finally {
        await within.close();
      }
      void lenient;
    } finally {
      await strict.close();
      await lenient.close();
    }
  });

  it("returns 503 when the store rejects", async () => {
    const store: SessionStore = { findByHash: async () => Promise.reject(new Error("db down")) };
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(503);
      expect(await res.json()).toEqual({ error: "temporarily_unavailable" });
      expect(res.headers.get("www-authenticate")).toBeNull();
    } finally {
      await s.close();
    }
  });

  it.each([null, "boom", undefined])("returns 503 when the store throws %s", async (value) => {
    const store: SessionStore = {
      findByHash: () => {
        throw value;
      },
    };
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(503);
    } finally {
      await s.close();
    }
  });

  it("returns 503 within the budget when the store hangs", async () => {
    const store: SessionStore = { findByHash: () => new Promise(() => {}) };
    const s = await serve(makeApp({ sessions: store, storeTimeoutMs: 50 }));
    try {
      const start = Date.now();
      const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(503);
      expect(Date.now() - start).toBeLessThan(1000);
    } finally {
      await s.close();
    }
  });

  it("passes only the hash to the store", async () => {
    const spy = storeWith({});
    const s = await serve(makeApp({ sessions: spy }));
    try {
      await fetch(s.url + "/me", { headers: { authorization: `Bearer ${TOKEN}` } }).then((r) => r.text());
      expect(spy.findByHash).toHaveBeenCalledTimes(1);
      const [hash, opts] = spy.findByHash.mock.calls[0]!;
      expect(hash).toBe(hashSessionToken(TOKEN));
      expect(hash).not.toBe(TOKEN);
      expect(opts.signal).toBeInstanceOf(AbortSignal);
    } finally {
      await s.close();
    }
  });

  it("optionalAuth passes through when absent and 401s when invalid", async () => {
    const absent = await get("/opt");
    expect(absent.status).toBe(200);
    expect(await absent.json()).toEqual({ present: false });

    const invalid = await get("/opt", { authorization: "Bearer nope" });
    expect(invalid.status).toBe(401);
  });

  it("skipPreflight: OPTIONS bypasses the store when true, 401 when false", async () => {
    const spyTrue = storeWith({});
    const onTrue = await serve(makeApp({ sessions: spyTrue, skipPreflight: true }));
    const spyFalse = storeWith({});
    const onFalse = await serve(makeApp({ sessions: spyFalse, skipPreflight: false }));
    try {
      const pass = await fetch(onTrue.url + "/me", { method: "OPTIONS" });
      expect(pass.status).toBe(200);
      expect(spyTrue.findByHash).not.toHaveBeenCalled();

      const deny = await fetch(onFalse.url + "/me", { method: "OPTIONS" });
      expect(deny.status).toBe(401);
    } finally {
      await onTrue.close();
      await onFalse.close();
    }
  });

  it("requireScope allows when the scope is present and 403s otherwise", async () => {
    const ok = await get("/admin", { authorization: `Bearer ${TOKEN}` });
    expect(ok.status).toBe(200);

    const token = createSessionToken();
    const store = storeWith({
      [hashSessionToken(token)]: { subjectId: "u", expiresAt: FUTURE(), scopes: ["user"] },
    });
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/admin", { headers: { authorization: `Bearer ${token}` } });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "forbidden" });
    } finally {
      await s.close();
    }
  });

  it("requireScope with an array uses AND semantics", async () => {
    const token = createSessionToken();
    const store = storeWith({
      [hashSessionToken(token)]: { subjectId: "u", expiresAt: FUTURE(), scopes: ["a"] },
    });
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/both", { headers: { authorization: `Bearer ${token}` } });
      expect(res.status).toBe(403);
    } finally {
      await s.close();
    }
  });

  it("requireScope without req.auth returns 401", async () => {
    const res = await get("/scope-no-auth");
    expect(res.status).toBe(401);
  });

  it("serialized responses and onAuthFailure payloads never contain the token", async () => {
    const seen: AuthFailureInfo[] = [];
    const logged: string[] = [];
    const s = await serve(makeApp({ sessions, onAuthFailure: (i) => seen.push(i) }));
    const bogus = createSessionToken();
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: `Bearer ${bogus}` } });
      logged.push(await res.text(), JSON.stringify(seen));
      for (const entry of logged) {
        expect(entry).not.toContain(bogus);
        expect(entry).not.toContain(bogus.slice(0, 20));
      }
    } finally {
      await s.close();
    }
  });

  it("an onAuthFailure that throws does not break the response", async () => {
    const s = await serve(
      makeApp({
        sessions,
        onAuthFailure: () => {
          throw new Error("observer broke");
        },
      }),
    );
    try {
      const res = await get("/me");
      expect(res.status).toBe(401);
    } finally {
      await s.close();
    }
  });

  it("gives 100 concurrent requests independent req.auth", async () => {
    const tokens = Array.from({ length: 100 }, () => createSessionToken());
    const store = storeWith(
      Object.fromEntries(
        tokens.map((t, i) => [
          hashSessionToken(t),
          { subjectId: `user-${i}`, expiresAt: FUTURE(), scopes: [`s${i}`] },
        ]),
      ),
    );
    const s = await serve(makeApp({ sessions: store }));
    try {
      const results = await Promise.all(
        tokens.map((t) => fetch(s.url + "/me", { headers: { authorization: `Bearer ${t}` } }).then((r) => r.json())),
      );
      results.forEach((body, i) => {
        expect(body).toEqual({ subjectId: `user-${i}`, scopes: [`s${i}`] });
      });
    } finally {
      await s.close();
    }
  });
});

describe("option validation", () => {
  const sessions = storeWith({});

  it.each([NaN, Infinity, -Infinity, -1, "5" as unknown as number])(
    "rejects clockSkewSeconds=%s at construction",
    (value) => {
      expect(() => createAuth({ sessions, clockSkewSeconds: value })).toThrow(TypeError);
    },
  );

  it.each([NaN, Infinity, 0, -1, 1.5])("rejects storeTimeoutMs=%s at construction", (value) => {
    expect(() => createAuth({ sessions, storeTimeoutMs: value })).toThrow(TypeError);
  });

  it("rejects a store without findByHash", () => {
    expect(() => createAuth({ sessions: {} as SessionStore })).toThrow(TypeError);
    expect(() => createAuth(undefined as unknown as AuthOptions)).toThrow(TypeError);
  });

  it("accepts clockSkewSeconds=0 and the defaults", () => {
    expect(() => createAuth({ sessions, clockSkewSeconds: 0 })).not.toThrow();
    expect(() => createAuth({ sessions })).not.toThrow();
  });

  it.each([[[]], [[""]], [""], [["a", 1 as unknown as string]]])("requireScope(%j) throws", (scope) => {
    const auth = createAuth({ sessions });
    expect(() => auth.requireScope(scope)).toThrow(TypeError);
  });
});

describe("record validation and header parsing", () => {
  async function statusFor(record: unknown, authorization?: string): Promise<{ status: number; body: unknown }> {
    const token = createSessionToken();
    const store: SessionStore = {
      findByHash: async (hash) => (hash === hashSessionToken(token) ? (record as SessionRecord) : null),
    };
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: authorization ?? "Bearer " + token } });
      return { status: res.status, body: await res.json() };
    } finally {
      await s.close();
    }
  }

  it("rejects a session expired well beyond the skew window", async () => {
    const expired = { subjectId: "u", expiresAt: Date.now() - 86_400_000 };
    expect((await statusFor(expired)).status).toBe(401);
  });

  it.each([
    ["string scopes", { scopes: "admin" }],
    ["non-string scope entries", { scopes: ["ok", 1] }],
    ["numeric sessionId", { sessionId: 42 }],
    ["array metadata", { metadata: [1, 2] }],
    ["string metadata", { metadata: "x" }],
  ])("returns 503 for a record with %s", async (_label, extra) => {
    const result = await statusFor({ subjectId: "u", expiresAt: FUTURE(), ...extra });
    expect(result.status).toBe(503);
  });

  it("treats null optional fields as absent", async () => {
    const result = await statusFor({ subjectId: "u", expiresAt: FUTURE(), sessionId: null, scopes: null, metadata: null });
    expect(result).toEqual({ status: 200, body: { subjectId: "u", scopes: [] } });
  });

  it("accepts multiple spaces after the Bearer scheme", async () => {
    const token = createSessionToken();
    const store = storeWith({ [hashSessionToken(token)]: { subjectId: "u", expiresAt: FUTURE() } });
    const s = await serve(makeApp({ sessions: store }));
    try {
      const res = await fetch(s.url + "/me", { headers: { authorization: "Bearer   " + token } });
      expect(res.status).toBe(200);
    } finally {
      await s.close();
    }
  });
});
