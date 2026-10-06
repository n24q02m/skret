const fs = require('fs');
let code = fs.readFileSync('hub/src/render.ts', 'utf8');
code = code.replace(
  'const staleBadge = isStale(m.generated_at, now) ? `<span class="badge stale">stale</span>` : "";',
  'const staleBadge = isStale(m.generated_at, now) ? `<span class="badge stale" title="Manifest is older than 48h">stale</span>` : "";'
);
code = code.replace(
  'return page(`<h1>skret vault dashboard</h1>${body}${logout}`);',
  'return page(`<h1>skret vault dashboard</h1>${body}${logout}`, "skret vault dashboard");'
);
fs.writeFileSync('hub/src/render.ts', code);
