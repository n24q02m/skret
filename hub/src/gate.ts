import { DurableObject } from "cloudflare:workers";
import type { Env } from "./types";

// LOGIN_ATTEMPTS/LOGIN_WINDOW_MS is the real login limit. The LOGIN_LIMIT
// binding in router.ts is nominally 5/60s too, but it does not actually hold
// that line (see the comment on loginAllowed), so this object is what the
// documented "5 attempts a minute" means.
export const LOGIN_ATTEMPTS = 5;
export const LOGIN_WINDOW_MS = 60_000;

// Exported so the test that inspects this object's storage names the same key
// the object writes, instead of a string literal that could drift out of step
// with it silently.
export const ATTEMPTS_KEY = "attempts";

// One instance per client address (router.ts derives the name from
// CF-Connecting-IP), so guessing runs from different addresses never share a
// budget and one attacker cannot lock the dashboard for everyone.
//
// A Durable Object rather than the Rate Limiting binding because only one
// instance of a given object exists worldwide, so every attempt from an
// address lands on the same counter no matter which isolate, machine or
// location served the request. That is the exact property the binding does
// not have -- Cloudflare documents it as "permissive, eventually consistent,
// and intentionally designed to not be used as an accurate accounting
// system", with each isolate checking "its locally cached value".
//
// A Durable Object rather than KV because KV is eventually consistent across
// locations, which is the same hole one layer down.
export class LoginGate extends DurableObject<Env> {
  // Records an attempt and reports whether it is allowed. Both the count and
  // the decision live here, so a caller cannot forget to record.
  async attempt(): Promise<boolean> {
    // Read inside the object, not passed in by the Worker: the caller must not
    // be able to move the window by sending its own clock.
    const now = Date.now();
    const stored = (await this.ctx.storage.get<number[]>(ATTEMPTS_KEY)) ?? [];
    const recent = stored.filter((t) => now - t < LOGIN_WINDOW_MS);

    const allowed = recent.length < LOGIN_ATTEMPTS;
    // A blocked attempt is deliberately NOT recorded. Recording it would make
    // a client that keeps hammering push its own window forward forever and
    // never recover, which turns a rate limit into a permanent lockout an
    // attacker can inflict on the owner's address.
    if (allowed) recent.push(now);

    await this.ctx.storage.put(ATTEMPTS_KEY, recent);
    // Storage is per address, so without this every address that ever guessed
    // once would keep a row for good. Set on every attempt, so the alarm sits
    // one window past the LAST one and the object drops itself when the
    // client goes quiet.
    await this.ctx.storage.setAlarm(now + LOGIN_WINDOW_MS);
    return allowed;
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
