import type { Env } from "./types";
import { handleIngest } from "./ingest";
import { checkPassword, mintSession, verifySession, SESSION_TTL } from "./auth";
import { getAllManifests } from "./store";
import { renderDashboard, renderLogin } from "./render";

const COOKIE = "session";

export async function handleRequest(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);

  if (req.method === "GET" && pathname === "/healthz") {
    return json({ ok: true });
  }
  if (req.method === "POST" && pathname === "/api/manifest") {
    return handleIngest(req, env);
  }
  if (req.method === "POST" && pathname === "/login") {
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

async function handleLogin(req: Request, env: Env): Promise<Response> {
  let password: string;
  try {
    const form = await req.formData();
    password = String(form.get("password") ?? "");
  } catch {
    return html(renderLogin("bad request"), 400);
  }
  if (!checkPassword(password, env.RELAY_PASSWORD)) {
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
