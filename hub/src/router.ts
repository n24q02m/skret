import { getContainer } from "@cloudflare/containers";
import type { Env, SyncHealth } from "./types";
import { handleIngest } from "./ingest";
import { checkPassword, mintSession, verifySession, SESSION_TTL } from "./auth";
import { getAllManifests } from "./store";
import { renderDashboard, renderLogin } from "./render";

const COOKIE = "session";

export async function handleRequest(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);

  if (req.method === "GET" && pathname === "/healthz") {
    return handleHealthz(env);
  }
  if (req.method === "POST" && pathname === "/api/manifest") {
    if (!(await allow(env.INGEST_LIMIT, req))) {
      return rateLimited("rate limited");
    }
    return handleIngest(req, env);
  }
  if (req.method === "POST" && pathname === "/login") {
    // Ahead of reading the form and comparing the password, so a flood never
    // reaches the constant-time compare.
    if (!(await loginAllowed(env, req))) {
      return html(renderLogin("too many attempts -- wait a minute"), 429);
    }
    return handleLogin(req, env);
  }
  if (req.method === "POST" && pathname === "/logout") {
    return handleLogout();
  }
  if (req.method === "GET" && pathname === "/") {
    return handleDashboard(req, env);
  }
  return notFound();
}

// The login limit, in two layers, because the cheap layer does not hold the
// line it appears to.
//
// LOGIN_LIMIT (the Rate Limiting binding) goes first and costs nothing: no
// network call, and it turns away a client hammering down one connection
// before anything else runs. It cannot BE the limit, though. Cloudflare
// documents the binding as "permissive, eventually consistent, and
// intentionally designed to not be used as an accurate accounting system",
// with each isolate checking "its locally cached value". Measured against
// this deployed Worker on 2026-08-09: 15 wrong passwords, a fresh TCP
// connection each, all served by one location (cf-ray ...-HKG), produced
// zero 429s -- while 6 requests down a single reused connection were refused
// from the 4th. An attacker does not need to be distributed to walk past it;
// a new connection per guess is enough. An earlier version of this comment
// claimed the bucket was per location and that beating it took spreading
// across PoPs. That was wrong, and it made the exposure look smaller than it
// is.
//
// So LOGIN_GATE decides: one Durable Object per client address means one
// counter worldwide for that address, which is what makes the documented
// 5-a-minute actually true. It costs one Durable Object request per attempt
// that gets past the binding. Worth paying on a login form guarding one
// shared password; not worth it on /api/manifest, which keeps the cheap
// limiter alone because its bearer token is a high-entropy secret -- the
// exposure there is cost and noise, not a guessable credential.
//
// Neither layer replaces the password. They buy time; they do not make
// guessing impossible. A global cap in front of the Worker would belong in a
// zone WAF rate-limiting rule, which needs a zone-scoped token the CD deploy
// token deliberately does not carry (see wrangler.deploy.template.jsonc).
async function loginAllowed(env: Env, req: Request): Promise<boolean> {
  if (!(await allow(env.LOGIN_LIMIT, req))) return false;
  const gate = env.LOGIN_GATE.get(env.LOGIN_GATE.idFromName(clientKey(req)));
  return gate.attempt();
}

async function allow(limiter: RateLimit, req: Request): Promise<boolean> {
  const { success } = await limiter.limit({ key: clientKey(req) });
  return success;
}

// A request with no CF-Connecting-IP -- only reachable off Cloudflare's edge,
// e.g. in tests -- shares one counter instead of escaping the limit.
function clientKey(req: Request): string {
  return req.headers.get("CF-Connecting-IP") ?? "no-ip";
}

function rateLimited(body: string): Response {
  return new Response(body, {
    status: 429,
    headers: { "Content-Type": "text/plain", "Retry-After": "60", ...SECURITY_HEADERS },
  });
}

// The key /healthz reads. It is never written, so the probe is a miss by
// design -- a miss still requires the binding to resolve and KV to answer,
// which is the whole question being asked.
const HEALTH_PROBE_KEY = "healthz:probe";

// /healthz used to answer a static {ok:true}. That is not a health signal:
// this Worker's only dependency is VAULT_KV, so a wrong namespace id or a
// KV outage takes GET / down while /healthz keeps telling the monitor
// everything is fine.
//
// It probes with get(), not list(), even though getAllManifests() lists.
// On the KV free plan a read costs against 100,000/day but a list costs
// against 1,000/day -- a monitor polling once a minute is 1,440 lists,
// so the "obvious" list-based probe would exhaust the list quota and start
// failing the dashboard it exists to watch. A get on a missing key
// exercises the same binding and the same round trip for 1/100th of the
// budget.
//
// The failure body says "error" and never the exception: this route has no
// auth, so it must not narrate account internals to anyone who curls it.
async function handleHealthz(env: Env): Promise<Response> {
  try {
    await env.VAULT_KV.get(HEALTH_PROBE_KEY);
  } catch {
    return json({ ok: false, kv: "error", sync: null }, 503);
  }

  let sync: SyncHealth | null = null;
  try {
    const health = await getContainer(env.SYNC).getSyncHealth();
    sync = projectSyncHealth(health);
  } catch {
    // Sync freshness is informative; a transient RPC failure must not turn
    // the unauthenticated health probe into an internal-error disclosure.
  }
  return json({ ok: true, kv: "ok", sync });
}

function projectSyncHealth(value: unknown): SyncHealth | null {
  if (value === null || typeof value !== "object") return null;
  const candidate = value as Partial<SyncHealth>;
  if (typeof candidate.active !== "boolean") return null;

  const lastSuccessAt =
    typeof candidate.last_success_at === "string" &&
    Number.isFinite(Date.parse(candidate.last_success_at))
      ? candidate.last_success_at
      : null;
  const ageSeconds =
    typeof candidate.age_seconds === "number" &&
    Number.isFinite(candidate.age_seconds) &&
    candidate.age_seconds >= 0
      ? Math.floor(candidate.age_seconds)
      : null;

  return {
    active: candidate.active,
    last_success_at: lastSuccessAt,
    age_seconds: ageSeconds,
  };
}

async function handleLogin(req: Request, env: Env): Promise<Response> {
  let password: string;
  try {
    const form = await req.formData();
    password = String(form.get("password") ?? "");
  } catch {
    return html(renderLogin("bad request"), 400);
  }
  if (!(await checkPassword(password, env.RELAY_PASSWORD))) {
    return html(renderLogin("wrong password"), 401);
  }
  const token = await mintSession(env.RELAY_PASSWORD, SESSION_TTL);
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie": `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`,
    },
  });
}

// handleLogout clears the session cookie (Max-Age=0, the standard
// immediate-expiry idiom) and redirects to "/", which then falls back to
// the login form since the cookie is gone. POST-only (not a bare link)
// because it mutates client-visible session state. Note this scheme has
// no server-side session store to revoke from -- the signed cookie stays
// cryptographically valid until its embedded exp either way; clearing it
// is a client-side "forget this browser's copy" action, which is the
// correct and complete fix for a stateless-cookie design (adding a real
// revocation store is out of scope for this wave).
function handleLogout(): Response {
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie": `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`,
    },
  });
}

async function handleDashboard(req: Request, env: Env): Promise<Response> {
  const cookie = readCookie(req, COOKIE);
  if (!cookie || !(await verifySession(env.RELAY_PASSWORD, cookie))) {
    return html(renderLogin(), 200);
  }
  const manifests = await getAllManifests(env.VAULT_KV);
  return html(renderDashboard(manifests), 200);
}

function readCookie(req: Request, name: string): string | null {
  const raw = req.headers.get("Cookie");
  if (!raw) return null;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

// SECURITY_HEADERS is shared by every content response this Worker returns --
// html(), json(), and notFound() alike -- so /healthz and 404s carry the
// same Cache-Control/CSP/nosniff discipline as the HTML routes instead of
// silently omitting them (audit finding M6). The 303 redirects (login
// success, logout) are bare Response objects and carry only Location +
// Set-Cookie, not these headers.
const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'",
};

function withSecurityHeaders(body: BodyInit | null, status: number, contentType: string): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": contentType, ...SECURITY_HEADERS },
  });
}

export function json(obj: unknown, status = 200): Response {
  return withSecurityHeaders(JSON.stringify(obj), status, "application/json");
}

function html(body: string, status: number): Response {
  return withSecurityHeaders(body, status, "text/html; charset=utf-8");
}

export function notFound(): Response {
  return withSecurityHeaders("not found", 404, "text/plain");
}

// serverError is exported for index.ts's top-level catch (the Durable
// boundary that must never leak a stack/exception to the client), so the
// one remaining bare-Response path also carries the shared headers.
export function serverError(): Response {
  return withSecurityHeaders("internal error", 500, "text/plain");
}
