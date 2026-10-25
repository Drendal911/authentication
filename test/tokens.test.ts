import { describe, expect, it } from "vitest";
import { createSessionToken, hashSessionToken } from "../src/tokens.js";

describe("token helpers", () => {
  it("pins the hash output (persisted format golden value)", () => {
    expect(hashSessionToken("test-token")).toBe("TF3Jt3CJBfd_Xl0WMWtd-0JeaMsybc1VqGDpCncHAx4");
  });

  it("creates 43-char base64url tokens", () => {
    expect(createSessionToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("generates 10,000 unique, well-formed tokens", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10_000; i++) {
      const token = createSessionToken();
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(token).not.toMatch(/[+/=]/);
      seen.add(token);
    }
    expect(seen.size).toBe(10_000);
  });

  it("hashes deterministically to 43 chars", () => {
    const h = hashSessionToken("abc");
    expect(h).toBe(hashSessionToken("abc"));
    expect(h).toHaveLength(43);
  });
});
