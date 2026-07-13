import type { Manifest } from "./types";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// KNOWN_STATUS maps the current status enum to its own badge/summary
// label. Anything else (a manifest written by the pre-Wave-3 CLI, still
// carrying "in-sync" | "drift" | "missing" until the next push overwrites
// it) falls back to the "other" CSS class in statusClass() below, so
// rendering never throws on stored data older than the code reading it.
const KNOWN_STATUS = new Set(["present", "absent", "unknown"]);

function statusClass(status: string): string {
  return KNOWN_STATUS.has(status) ? status : "other";
}

// STALE_MS: a card whose manifest is older than this is flagged "stale" --
// the cron hasn't refreshed it, so its presence status may no longer
// reflect reality even though nothing about it is literally wrong.
const STALE_MS = 48 * 60 * 60 * 1000;

// relativeTime renders `iso` (a manifest's generated_at) relative to `now`
// (both parseable by Date.parse) as a short "Xm/h/d ago" string. Exported
// for direct unit testing.
export function relativeTime(iso: string, now: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "unknown";
  const diffMs = now - then;
  if (diffMs < 60_000) return "just now";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// isStale reports whether `iso` is more than 48h before `now`. An
// unparseable timestamp is reported not-stale (fail safe: an unreadable
// date shouldn't paint a card as urgently wrong when the real problem is
// a malformed field, which is a separate concern). Exported for direct
// unit testing.
export function isStale(iso: string, now: number): boolean {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return false;
  return now - then > STALE_MS;
}

// summary renders "N keys — P present · A absent · U unknown", counting
// every (key, target) badge in the card and omitting any status with a
// zero count. Exported for direct unit testing.
export function summary(m: Manifest): string {
  const counts: Record<string, number> = { present: 0, absent: 0, unknown: 0 };
  for (const k of m.keys) {
    for (const t of Object.values(k.targets)) {
      counts[t.status] = (counts[t.status] ?? 0) + 1;
    }
  }
  const order = ["present", "absent", "unknown"];
  const parts = order.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  const total = m.keys.length;
  const suffix = parts.length ? ` — ${parts.join(" · ")}` : "";
  return `${total} key${total === 1 ? "" : "s"}${suffix}`;
}

const STYLE = `
  body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem;color:#1a1a1a;background:#fafafa}
  h1{font-size:1.3rem}
  .ns{margin:1.5rem 0;border:1px solid #ddd;border-radius:8px;overflow:hidden}
  .ns h2{font-size:1rem;margin:0;padding:.6rem 1rem;background:#f0f0f0;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
  .ns .meta{font-weight:normal;font-size:.8rem;color:#5a5a5a}
  .summary{padding:.4rem 1rem;font-size:.8rem;color:#5a5a5a;border-top:1px solid #eee}
  .tablewrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th,td{text-align:left;padding:.4rem 1rem;border-top:1px solid #eee}
  td.keyname{word-break:break-all}
  .fp{color:#5a5a5a}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.75rem;margin-right:.3rem}
  .present{background:#d7f5dd;color:#0a6b2e}
  .absent{background:#f5d7d7;color:#8a1a1a}
  .unknown{background:#e8e8e8;color:#4a4a4a}
  .other{background:#e8e8e8;color:#4a4a4a}
  .stale{background:#fde2c8;color:#9a4a0a}
  .empty{color:#5a5a5a;padding:2rem;text-align:center}
  form{display:flex;gap:.5rem;margin-top:1rem;align-items:center}
  input,button{padding:.5rem;font-size:1rem}
  .err{color:#8a1a1a}
`;

function page(inner: string): string {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>skret vault</title><style>${STYLE}</style></head>` +
    `<body>${inner}</body></html>`
  );
}

function renderNamespace(m: Manifest, now: number): string {
  const rows = m.keys
    .map((k) => {
      const badges = Object.entries(k.targets)
        .map(
          ([name, t]) =>
            `<span class="badge ${statusClass(t.status)}">${esc(name)}: ${esc(t.status)}</span>`,
        )
        .join("");
      return `<tr><td class="keyname">${esc(k.name)}</td><td class="fp">${esc(k.fingerprint)}</td><td>${badges}</td></tr>`;
    })
    .join("");
  const staleBadge = isStale(m.generated_at, now) ? `<span class="badge stale">stale</span>` : "";
  return (
    `<section class="ns"><h2>${esc(m.namespace)} &middot; ${esc(m.env)}` +
    ` <span class="meta">synced ${esc(relativeTime(m.generated_at, now))}</span>${staleBadge}</h2>` +
    `<div class="summary">${esc(summary(m))}</div>` +
    `<div class="tablewrap"><table><thead><tr><th>Key</th><th>Fingerprint</th><th>Targets</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></div></section>`
  );
}

export function renderDashboard(manifests: Manifest[], now: number = Date.now()): string {
  const sorted = [...manifests].sort((a, b) =>
    `${a.namespace}:${a.env}`.localeCompare(`${b.namespace}:${b.env}`),
  );
  const body = sorted.length
    ? sorted.map((mf) => renderNamespace(mf, now)).join("\n")
    : `<div class="empty">No manifests yet. Run <code>skret hub push</code>.</div>`;
  return page(`<h1>skret vault dashboard</h1>${body}`);
}

export function renderLogin(error?: string): string {
  const msg = error ? `<p class="err">${esc(error)}</p>` : "";
  return page(
    `<h1>skret vault</h1>${msg}` +
      `<form method="POST" action="/login">` +
      `<input type="password" name="password" placeholder="relay password" autofocus>` +
      `<button type="submit">Enter</button></form>`,
  );
}
