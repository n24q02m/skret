import type { Manifest } from "./types";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const STYLE = `
  body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem;color:#1a1a1a;background:#fafafa}
  h1{font-size:1.3rem}
  .ns{margin:1.5rem 0;border:1px solid #ddd;border-radius:8px;overflow:hidden}
  .ns h2{font-size:1rem;margin:0;padding:.6rem 1rem;background:#f0f0f0}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th,td{text-align:left;padding:.4rem 1rem;border-top:1px solid #eee}
  .fp{color:#888}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.75rem;margin-right:.3rem}
  .in-sync{background:#d7f5dd;color:#0a6b2e}
  .drift{background:#fde2c8;color:#9a4a0a}
  .missing{background:#f5d7d7;color:#8a1a1a}
  .empty{color:#888;padding:2rem;text-align:center}
  form{display:flex;gap:.5rem;margin-top:1rem}
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

function renderNamespace(m: Manifest): string {
  const rows = m.keys
    .map((k) => {
      const badges = Object.entries(k.targets)
        .map(
          ([name, t]) =>
            `<span class="badge ${esc(t.status)}">${esc(name)}: ${esc(t.status)}</span>`,
        )
        .join("");
      return `<tr><td>${esc(k.name)}</td><td class="fp">${esc(k.fingerprint)}</td><td>${badges}</td></tr>`;
    })
    .join("");
  return (
    `<section class="ns"><h2>${esc(m.namespace)} &middot; ${esc(m.env)}</h2>` +
    `<table><thead><tr><th scope="col">Key</th><th scope="col">Fingerprint</th><th scope="col">Targets</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></section>`
  );
}

export function renderDashboard(manifests: Manifest[]): string {
  const sorted = [...manifests].sort((a, b) =>
    `${a.namespace}:${a.env}`.localeCompare(`${b.namespace}:${b.env}`),
  );
  const body = sorted.length
    ? sorted.map(renderNamespace).join("\n")
    : `<div class="empty">No manifests yet. Run <code>skret hub push</code>.</div>`;
  return page(`<h1>skret vault dashboard</h1>${body}`);
}

export function renderLogin(error?: string): string {
  const msg = error ? `<p class="err" role="alert">${esc(error)}</p>` : "";
  return page(
    `<h1>skret vault</h1>${msg}` +
      `<form method="POST" action="/login">` +
      `<input type="password" name="password" aria-label="Relay password" placeholder="relay password" autofocus>` +
      `<button type="submit">Enter</button></form>`,
  );
}
