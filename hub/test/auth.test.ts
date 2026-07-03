import { describe, it, expect } from "vitest";
import { checkPassword, mintSession, verifySession, SESSION_TTL } from "../src/auth";

const SECRET = "test-relay-password";

describe("checkPassword", () => {
  it("true for exact match", () => {
    expect(checkPassword("hunter2", "hunter2")).toBe(true);
  });
  it("false for mismatch", () => {
    expect(checkPassword("hunter2", "hunter3")).toBe(false);
  });
  it("false for different length", () => {
    expect(checkPassword("short", "longerpass")).toBe(false);
  });
});

describe("signed session cookie", () => {
  it("mints a cookie that verifies", async () => {
    const cookie = await mintSession(SECRET, SESSION_TTL);
    expect(await verifySession(SECRET, cookie)).toBe(true);
  });
  it("rejects a tampered payload", async () => {
    const cookie = await mintSession(SECRET, SESSION_TTL);
    const [, sig] = cookie.split(".");
    const forged = `${btoa('{"exp":9999999999}').replace(/=+$/, "")}.${sig}`;
    expect(await verifySession(SECRET, forged)).toBe(false);
  });
  it("rejects a cookie signed with a different secret", async () => {
    const cookie = await mintSession("other-secret", SESSION_TTL);
    expect(await verifySession(SECRET, cookie)).toBe(false);
  });
  it("rejects an expired cookie", async () => {
    const cookie = await mintSession(SECRET, -10); // already expired
    expect(await verifySession(SECRET, cookie)).toBe(false);
  });
  it("rejects a malformed cookie", async () => {
    expect(await verifySession(SECRET, "garbage")).toBe(false);
  });
});
