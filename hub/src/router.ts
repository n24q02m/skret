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
  if (req.method === "GET" && pathname === "/") {
    return handleDashboard(req, env);
  }
  return new Response("not found", { status: 404 });
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

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function html(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
    },
  });
}
