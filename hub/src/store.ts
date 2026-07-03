import type { Manifest } from "./types";

const PREFIX = "manifest:";

export function manifestKey(ns: string, env: string): string {
  return `${PREFIX}${ns}:${env}`;
}

export async function putManifest(kv: KVNamespace, m: Manifest): Promise<void> {
  await kv.put(manifestKey(m.namespace, m.env), JSON.stringify(m), {
    metadata: { updated: m.generated_at },
  });
}

export async function getAllManifests(kv: KVNamespace): Promise<Manifest[]> {
  const out: Manifest[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix: PREFIX, cursor });
    for (const k of page.keys) {
      const raw = await kv.get(k.name);
      if (raw) out.push(JSON.parse(raw) as Manifest);
    }
    if (page.list_complete) {
      cursor = undefined;
    } else {
      cursor = page.cursor;
    }
  } while (cursor);
  return out;
}
