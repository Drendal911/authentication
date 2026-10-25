# @drendal911/authentication

Opaque session-token Bearer middleware for Express services running on the same host. Zero runtime dependencies.

Tokens are random, not JWTs. Verification hashes the token with SHA-256 and looks the hash up in an injected, read-only `SessionStore`. Deleting the hash from the store ends the session immediately.

This package **validates** credentials. It never issues them, never writes to storage, and never caches lookups.

## Install

```sh
npm install @drendal911/authentication
```

Published to GitHub Packages. Add a `.npmrc` entry that maps the `@drendal911` scope to `https://npm.pkg.github.com` and supplies a token with `read:packages`.

Requires Node.js >= 22 and Express >= 4 (peer dependency).

## Quickstart

```ts
import express from "express";
import { createAuth, redactHeaders, type SessionStore } from "@drendal911/authentication";

const sessions: SessionStore = {
  async findByHash(hash, { signal }) {
    // Look up an ACTIVE session by hash. Exact key lookup only.
    // Return null if not found. May reject; failures deny the request.
    return db.sessions.get(hash, { signal }); // your code
  },
};

const auth = createAuth({
  sessions,
  realm: "api",
  onAuthFailure: ({ reason, requestId }) => {
    logger.info({ reason, requestId }); // never includes the token
  },
});

const app = express();
app.use("/api", auth.requireAuth);
app.get("/api/me", (req, res) => {
  res.json({ subjectId: req.auth!.subjectId });
});
```

Log request headers only through `redactHeaders(req.headers)`. It replaces `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, and `x-api-key` with `[REDACTED]`.

## API

- `createAuth(options)` returns `{ requireAuth, optionalAuth, requireScope(scope) }`.
  - `requireAuth`: 401 unless a valid token is present.
  - `optionalAuth`: no header gives `next()` with `req.auth` undefined. A present but invalid token is still a 401. It is never a silent passthrough.
  - `requireScope(scope | scope[])`: 403 if scopes are missing. An array means **all listed scopes are required (AND)**. Mount after `requireAuth`. Missing `req.auth` gives 401.
- `createSessionToken()` returns 32 CSPRNG bytes, base64url (43 chars).
- `hashSessionToken(token)` returns SHA-256 of the UTF-8 token, base64url (43 chars).
- `forwardAuth(req)` and `redactHeaders(headers)`: see below.

Options: `realm` (default `"api"`), `clockSkewSeconds` (default 5), `storeTimeoutMs` (default 1000), `skipPreflight` (default false), `onAuthFailure`.

`createAuth` throws a `TypeError` at startup if `sessions.findByHash` is missing, `clockSkewSeconds` is not a finite number >= 0, or `storeTimeoutMs` is not a positive integer. `requireScope` throws if given an empty array or a non-string/empty scope.

`req.auth` is a deep-frozen `AuthContext` with `subjectId`, `sessionId`, `scopes`, and `metadata`. It is namespaced deliberately so it does not collide with `req.user` or `req.session`.

## Responses

| Case | Status | Body | Header |
|---|---|---|---|
| Missing token (`requireAuth`) | 401 | `{"error":"unauthorized"}` | `WWW-Authenticate: Bearer realm="api"` |
| Malformed, unknown, or expired | 401 | `{"error":"unauthorized"}` | `WWW-Authenticate: Bearer realm="api", error="invalid_token"` |
| Insufficient scope | 403 | `{"error":"forbidden"}` | `WWW-Authenticate: Bearer realm="api", error="insufficient_scope"` |
| Store error or timeout | 503 | `{"error":"temporarily_unavailable"}` | none |

Every auth response carries `Cache-Control: no-store`. Unknown and expired produce the same body; the distinction goes only to `onAuthFailure`.

## Issuer contract (database service)

The issuing service must follow these rules exactly:

1. Generate tokens with `createSessionToken()`.
2. Persist **only** `hashSessionToken(token)` as the store key. Never store the plaintext.
3. Set a TTL on the key that is at least `expiresAt`.
4. Return the plaintext token to the client exactly once. Never log it on the issuance path.
5. Look up by exact hash key. No prefix scans, no `KEYS`, no `SCAN` on the hot path.
6. On privilege change, rotate the session. This package cannot enforce rotation.

## Pinned format (warning)

The token format and the hash are a **persisted contract**. Changing the algorithm, encoding (`base64` vs `base64url`, hex), or the token length invalidates every live session. The golden-value test in `test/tokens.test.ts` fails if the output changes. A change requires a dual-read migration, not a version bump.

## Threat model

- **SHA-256 is sufficient** because the input is 256 bits of CSPRNG output. A slow KDF or salt would break exact-key lookup and add nothing against a guess space this large.
- **No in-process cache.** A cache would create a stale-allow window after logout and defeat instant revocation.
- **`clockSkewSeconds`** tolerates clock drift between the store and this host. Larger values widen the window in which an expired session is still accepted. The default is 5.
- **Single-host assumption.** Instant revocation holds because all services read the same store. Multi-region or replicated stores need their own consistency analysis.
- **Fail closed.** Store errors, timeouts, bad records, and unexpected exceptions return 503. They never pass through.
- **Never rejects.** Middleware catches everything and always calls `next()` or responds. Auth failures never call `next(err)`.

## Why query-string tokens and cookies are unsupported

Only the `Authorization` header is read. This is an intentional refusal, not an omission:

- Query strings end up in access logs, proxy logs, and browser history.
- Cookies bring CSRF obligations that a Bearer header avoids.

## Service-to-service: token relay

Services on this host forward the caller's existing token. Do not invent a second credential type.

```ts
const res = await fetch(otherServiceUrl, {
  method: "POST",
  headers: { "content-type": "application/json", ...forwardAuth(req) },
  body: JSON.stringify(payload),
});
```

Rules:

- Forward only to **trusted internal services on this host**. Never relay a token to a third party.
- Relay the same token or nothing. Never mint a derived or downgraded token.
- Never log the relayed header. Use `redactHeaders`.
- Do not call `forwardAuth` inside auth middleware. Relaying is an explicit choice at each call site.
- **Loopback is not identity.** Do not treat "the request came from `127.0.0.1`" as authentication.

Out of scope: machine-to-machine calls with no user context (cron jobs, queue workers). These need a separate mechanism.

## CORS

Mount `cors()` **before** auth, or set `skipPreflight: true`. Otherwise browser preflight `OPTIONS` requests get a 401.

## Default-deny

Mount auth at the app or router level, so newly added routes are not accidentally public.

## Session rotation

Rotating the session on a privilege change is the issuer's responsibility. This package cannot enforce it.

## Deviations from a naive reading

- On a denial where `res.headersSent` is already true, the middleware destroys the socket rather than calling `next()`. Calling `next()` there would fail open.
- A 403 from `requireScope` includes `error="insufficient_scope"` (RFC 6750).
- A store record with an invalid shape, a bad `expiresAt`, or non-cloneable metadata is treated as `store_error`. This includes `sessionId` that is not a string, `scopes` that is not an array of strings, and `metadata` that is not a plain object. `null` in an optional field is treated as absent.
- A numeric `expiresAt` is interpreted as epoch milliseconds.

## License

PolyForm Noncommercial 1.0.0. See `LICENSE`. Noncommercial use is permitted. Commercial use requires a separate license from the copyright holder.
