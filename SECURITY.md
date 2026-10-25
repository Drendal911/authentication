# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through GitHub Security Advisories on this repository, or contact the maintainer directly.

## Scope and guarantees

- Only `Authorization: Bearer` headers are read. Query strings and cookies are never accepted.
- Tokens are never logged, serialized, or included in error messages or `onAuthFailure` payloads.
- Store errors, timeouts, and unexpected exceptions fail closed (503). Auth failures never call `next(err)`.
- Session lookups are never cached in process memory, so revocation takes effect immediately.
- Token comparison happens in the store by exact hash lookup. No secret comparison is done in this package.

## Assumptions

- The package is used only by trusted services on a single host. Loopback origin is not an identity.
- The issuing service stores only `hashSessionToken(token)`, never the plaintext token.
- Session rotation on privilege change is the issuer's responsibility.
