import type { Env, Manifest } from "./types";
import { checkBearer } from "./auth";
import { putManifest } from "./store";

const VALID_STATUS = new Set(["in-sync", "drift", "missing"]);
// B1 never sends a value; reject anything value-like if a future producer regresses.
const FORBIDDEN_FIELDS = ["value", "secret", "text", "plaintext", "data"];

type ValidateResult =
  | { ok: true; manifest: Manifest }
  | { ok: false; error: string };

function hasForbidden(obj: Record<string, unknown>): string | null {
  for (const f of FORBIDDEN_FIELDS) if (f in obj) return f;
  return null;
}

export function validateManifest(body: unknown): ValidateResult {
  if (typeof body !== "object" || body === null) return { ok: false, error: "not an object" };
  const m = body as Record<string, unknown>;
  if (typeof m.namespace !== "string" || typeof m.env !== "string" || typeof m.generated_at !== "string")
    return { ok: false, error: "missing namespace/env/generated_at" };
  if (!Array.isArray(m.keys)) return { ok: false, error: "keys not an array" };
  for (const k of m.keys) {
    if (typeof k !== "object" || k === null) return { ok: false, error: "key not an object" };
    const kk = k as Record<string, unknown>;
    if (typeof kk.name !== "string" || typeof kk.fingerprint !== "string" || typeof kk.updated_at !== "string")
      return { ok: false, error: "key missing name/fingerprint/updated_at" };
    const kf = hasForbidden(kk);
    if (kf) return { ok: false, error: `forbidden field ${kf} on key` };
    if (typeof kk.targets !== "object" || kk.targets === null) return { ok: false, error: "targets not an object" };
    for (const t of Object.values(kk.targets as Record<string, unknown>)) {
      if (typeof t !== "object" || t === null) return { ok: false, error: "target not an object" };
      const tt = t as Record<string, unknown>;
      if (typeof tt.present !== "boolean") return { ok: false, error: "target.present not boolean" };
      if (typeof tt.status !== "string" || !VALID_STATUS.has(tt.status)) return { ok: false, error: "bad status enum" };
      const tf = hasForbidden(tt);
      if (tf) return { ok: false, error: `forbidden field ${tf} on target` };
    }
  }
  return { ok: true, manifest: body as Manifest };
}

export async function handleIngest(req: Request, env: Env): Promise<Response> {
  if (!checkBearer(req, env.SKRET_HUB_TOKEN)) {
    return new Response("unauthorized", { status: 401 });
  }
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return new Response("bad json", { status: 400 });
  }
  const result = validateManifest(body);
  if (!result.ok) {
    return new Response(`invalid manifest: ${result.error}`, { status: 400 });
  }
  await putManifest(env.VAULT_KV, result.manifest);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
