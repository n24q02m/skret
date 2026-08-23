import { verifySession } from "./auth";
import type { Env } from "./types";

const SESSION_COOKIE = "session";
const EXECUTOR_ORIGIN = "https://executor.internal";
const EXECUTOR_PATH = "/operator/executor-envelope";
const BODY_DIGEST_HEADER = "X-Skret-Body-Digest";
const CALLER_CONTEXT_HEADER = "X-Skret-Caller-Context";

export const MAX_EXECUTOR_ENVELOPE_BYTES = 1 << 20;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'",
};

/**
 * Authenticated public boundary for the private security executor. This route
 * deliberately treats the envelope as opaque bytes: validation, replay
 * protection, and all provider effects belong to the executor.
 */
export async function handleExecutorEnvelope(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") {
    return proxyResponse("method not allowed", 405, "text/plain; charset=utf-8", { Allow: "POST" });
  }

  const session = readCookie(req, SESSION_COOKIE);
  if (!session || !(await verifySession(env.RELAY_PASSWORD, session))) {
    return proxyResponse("unauthorized", 401, "text/plain; charset=utf-8");
  }

  const executor = env.EXECUTOR;
  if (!executor) {
    return proxyResponse("executor unavailable", 503, "text/plain; charset=utf-8");
  }

  const declaredLength = req.headers.get("Content-Length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (Number.isFinite(length) && length > MAX_EXECUTOR_ENVELOPE_BYTES) {
      return proxyResponse("payload too large", 413, "text/plain; charset=utf-8");
    }
  }

  let body: Uint8Array | null;
  try {
    body = await readBoundedBody(req);
  } catch {
    return proxyResponse("bad request", 400, "text/plain; charset=utf-8");
  }
  if (body === null) {
    return proxyResponse("payload too large", 413, "text/plain; charset=utf-8");
  }

  const bodyDigest = await sha256(body);
  const callerContext = await sha256(new TextEncoder().encode(`session:${session}`));
  const headers = new Headers({
    // The signed envelope client sends JSON. Keep the forwarded body opaque;
    // this value describes the endpoint contract without parsing the bytes.
    "Content-Type": "application/json",
    [BODY_DIGEST_HEADER]: `sha256:${bodyDigest}`,
    [CALLER_CONTEXT_HEADER]: `sha256:${callerContext}`,
  });
  const forwarded = new Request(`${EXECUTOR_ORIGIN}${EXECUTOR_PATH}`, {
    method: "POST",
    headers,
    body: body as BodyInit,
  });

  let upstream: Response;
  try {
    upstream = await executor.fetch(forwarded);
  } catch {
    return proxyResponse("executor unavailable", 502, "text/plain; charset=utf-8");
  }

  const responseHeaders = new Headers(SECURITY_HEADERS);
  const contentType = upstream.headers.get("Content-Type");
  if (contentType) responseHeaders.set("Content-Type", contentType);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
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

async function readBoundedBody(req: Request): Promise<Uint8Array | null> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (size + value.byteLength > MAX_EXECUTOR_ENVELOPE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The oversized result remains fail-closed even if cancellation fails.
        }
        return null;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Preserve the original read failure as a generic bad request.
    }
    throw error;
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function proxyResponse(
  body: string,
  status: number,
  contentType: string,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(body, {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": contentType, ...extraHeaders },
  });
}
