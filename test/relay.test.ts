import express from "express";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { forwardAuth } from "../src/relay.js";
import { redactHeaders } from "../src/redact.js";
import { createSessionToken } from "../src/tokens.js";

function fakeReq(headers: Record<string, string>): express.Request {
  return { headers } as unknown as express.Request;
}

describe("forwardAuth", () => {
  it("relays a valid-format bearer token unchanged", () => {
    const token = createSessionToken();
    expect(forwardAuth(fakeReq({ authorization: `bearer ${token}` }))).toEqual({
      Authorization: `Bearer ${token}`,
    });
  });

  it("normalizes multiple spaces after the scheme", () => {
    const token = createSessionToken();
    expect(forwardAuth(fakeReq({ authorization: "Bearer   " + token }))).toEqual({ Authorization: "Bearer " + token });
  });

  it("returns {} when absent or malformed", () => {
    expect(forwardAuth(fakeReq({}))).toEqual({});
    expect(forwardAuth(fakeReq({ authorization: "Basic abc" }))).toEqual({});
    expect(forwardAuth(fakeReq({ authorization: "Bearer short" }))).toEqual({});
  });
});

describe("redactHeaders", () => {
  it("redacts credential-bearing headers case-insensitively", () => {
    const out = redactHeaders({
      Authorization: "Bearer secret",
      cookie: "sid=secret",
      "Set-Cookie": "sid=secret",
      "x-api-key": "k",
      accept: "application/json",
    });
    expect(out).toEqual({
      Authorization: "[REDACTED]",
      cookie: "[REDACTED]",
      "Set-Cookie": "[REDACTED]",
      "x-api-key": "[REDACTED]",
      accept: "application/json",
    });
  });
});

describe("relay end to end", () => {
  it("forwards the same token to a downstream service that accepts it", async () => {
    const { createAuth } = await import("../src/session.js");
    const { hashSessionToken } = await import("../src/tokens.js");
    const token = createSessionToken();
    const store = {
      findByHash: async (hash: string) =>
        hash === hashSessionToken(token) ? { subjectId: "user-9", expiresAt: Date.now() + 60_000 } : null,
    };
    const auth = createAuth({ sessions: store });

    const downstream = express();
    downstream.get("/whoami", auth.requireAuth, (req, res) => {
      res.json({ subjectId: req.auth!.subjectId });
    });
    const upstream = express();
    upstream.get("/relay", (req, res, next) => {
      void (async () => {
        const r = await fetch(`http://127.0.0.1:${(downstreamServer.address() as AddressInfo).port}/whoami`, {
          headers: forwardAuth(req),
        });
        res.status(r.status).json(await r.json());
      })().catch(next);
    });

    const downstreamServer = await new Promise<import("node:http").Server>((resolve) => {
      const s = downstream.listen(0, "127.0.0.1", () => resolve(s));
    });
    const upstreamServer = await new Promise<import("node:http").Server>((resolve) => {
      const s = upstream.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const port = (upstreamServer.address() as AddressInfo).port;
      const res = await fetch(`http://127.0.0.1:${port}/relay`, {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(await res.json()).toEqual({ subjectId: "user-9" });
    } finally {
      await new Promise<void>((r) => upstreamServer.close(() => r()));
      await new Promise<void>((r) => downstreamServer.close(() => r()));
    }
  });
});
