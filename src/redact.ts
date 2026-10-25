const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-api-key",
]);

/**
 * Returns a copy of the headers safe to log. Credential-bearing headers are
 * replaced with "[REDACTED]". Use this in every logging example.
 */
export function redactHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name] = SENSITIVE_HEADERS.has(name.toLowerCase())
      ? "[REDACTED]"
      : Array.isArray(value)
        ? value.map(String).join(", ")
        : String(value);
  }
  return out;
}
