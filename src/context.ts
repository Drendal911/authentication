/** Authenticated context attached to req.auth. Deep-frozen. */
export interface AuthContext {
  readonly kind: "session";
  readonly subjectId: string;
  readonly sessionId?: string;
  readonly scopes: readonly string[];
  readonly metadata: Readonly<Record<string, unknown>>;
}

declare global {
  namespace Express {
    interface Request {
      /** Present only when auth middleware allowed the request. Frozen. */
      auth?: AuthContext;
    }
  }
}

/** Recursively freezes an object graph. Cycle-safe. */
export function deepFreeze<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) {
    return value;
  }
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    deepFreeze((value as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}
