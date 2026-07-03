import type { Env } from "./types";
import { handleIngest } from "./ingest";

export async function handleRequest(req: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(req.url);

  if (req.method === "GET" && pathname === "/healthz") {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (req.method === "POST" && pathname === "/api/manifest") {
    return handleIngest(req, env);
  }
  return new Response("not found", { status: 404 });
}
