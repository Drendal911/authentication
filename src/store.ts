/** Session store contract. Implemented by the consumer / database service. */
export interface SessionStore {
  /**
   * Look up an ACTIVE session by the SHA-256 hash of its token.
   * Return null when not found. May reject; callers fail closed.
   * Receives ONLY the hash, never the raw token.
   */
  findByHash(hash: string, opts: { signal: AbortSignal }): Promise<SessionRecord | null>;
}

export interface SessionRecord {
  /** Stable identifier for the authenticated principal. */
  subjectId: string;
  /** Absolute expiry. Re-checked by the middleware; the store is not trusted for this. */
  expiresAt: Date | number;
  sessionId?: string;
  scopes?: string[];
  /** Attached to req.auth.metadata verbatim; not interpreted. */
  metadata?: Record<string, unknown>;
}
