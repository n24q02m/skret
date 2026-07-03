import type { Env } from "./types";

export async function handleRequest(req: Request, _env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (req.method === "GET" && pathname === "/healthz") {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  return new Response("not found", { status: 404 });
}
