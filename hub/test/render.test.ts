import { describe, it, expect } from "vitest";
import { renderDashboard, renderLogin, relativeTime, isStale, summary } from "../src/render";
import type { Manifest } from "../src/types";

const FIXED_NOW = Date.parse("2026-07-13T12:00:00Z");

const m: Manifest = {
  namespace: "/klprism/prod",
  env: "prod",
  generated_at: "2026-07-03T10:00:00Z",
  keys: [
    {
      name: "DATABASE_URL",
      fingerprint: "a1b2c3d4",
      updated_at: "2026-07-01T00:00:00Z",
      targets: {
        "github:n24q02m/skret": { present: true, status: "present" },
        "cloudflare:worker": { present: false, status: "absent" },
      },
    },
  ],
};

describe("summary", () => {
  it("counts (key, target) badges by status and hides zero groups", () => {
    const manyAbsent: Manifest = {
      namespace: "/x/prod",
      env: "prod",
      generated_at: m.generated_at,
      keys: Array.from({ length: 3 }, (_, i) => ({
        name: `K${i}`,
        fingerprint: "ffffffff",
        updated_at: m.keys[0].updated_at,
        targets: { "github:o/r": { present: false, status: "absent" } },
      })),
    };
    expect(summary(manyAbsent)).toBe("3 keys — 3 absent");
  });
  it("shows a mixed count", () => {
    const mixed: Manifest = {
      namespace: "/x/prod",
      env: "prod",
      generated_at: m.generated_at,
      keys: [
        { name: "A", fingerprint: "f1", updated_at: m.keys[0].updated_at, targets: { t: { present: true, status: "present" } } },
        { name: "B", fingerprint: "f2", updated_at: m.keys[0].updated_at, targets: { t: { present: false, status: "unknown" } } },
      ],
    };
    expect(summary(mixed)).toBe("2 keys — 1 present · 1 unknown");
  });
  it("uses singular 'key' for exactly one", () => {
    const one: Manifest = { ...m, keys: [{ ...m.keys[0], targets: {} }] };
    expect(summary(one)).toBe("1 key");
  });
  it("aggregates legacy (pre-Wave-3) statuses into an 'other' bucket", () => {
    const legacy: Manifest = {
      namespace: "/x/prod",
      env: "prod",
      generated_at: m.generated_at,
      keys: [
        { name: "A", fingerprint: "f1", updated_at: m.keys[0].updated_at, targets: { t: { present: true, status: "missing" } } },
        { name: "B", fingerprint: "f2", updated_at: m.keys[0].updated_at, targets: { t: { present: true, status: "drift" } } },
      ],
    };
    expect(summary(legacy)).toBe("2 keys — 2 other");
  });
  it("shows a known bucket alongside the 'other' bucket in a mixed fixture", () => {
    const mixed: Manifest = {
      namespace: "/x/prod",
      env: "prod",
      generated_at: m.generated_at,
      keys: [
        { name: "A", fingerprint: "f1", updated_at: m.keys[0].updated_at, targets: { t: { present: true, status: "present" } } },
        { name: "B", fingerprint: "f2", updated_at: m.keys[0].updated_at, targets: { t: { present: true, status: "missing" } } },
      ],
    };
    expect(summary(mixed)).toBe("2 keys — 1 present · 1 other");
  });
});

describe("renderDashboard", () => {
  it("renders key name, fingerprint and per-target status", () => {
    const html = renderDashboard([m]);
    expect(html).toContain("DATABASE_URL");
    expect(html).toContain("a1b2c3d4");
    expect(html).toContain("present");
    expect(html).toContain("absent");
    expect(html).toContain("/klprism/prod");
  });
  it("shows an empty state with no manifests", () => {
    expect(renderDashboard([])).toContain("hub push");
  });
  it("escapes HTML in names (XSS guard)", () => {
    const evil: Manifest = { ...m, namespace: "<script>", keys: [] };
    const html = renderDashboard([evil]);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
  it("escapes single quotes in names", () => {
    const q: Manifest = { ...m, namespace: "a'b", keys: [] };
    const html = renderDashboard([q]);
    expect(html).toContain("a&#39;b");
    expect(html).not.toContain("a'b");
  });
  describe("statusClass fallback (forward-compat with pre-Wave-3 manifests)", () => {
    it("renders present/absent with their own badge class", () => {
      const html = renderDashboard([m]);
      expect(html).toContain('class="badge present"');
      expect(html).toContain('class="badge absent"');
    });
    it("falls back to the 'other' class for a legacy status string", () => {
      const legacy: Manifest = structuredClone(m);
      legacy.keys[0].targets["github:n24q02m/skret"] = { present: true, status: "in-sync" };
      const html = renderDashboard([legacy]);
      expect(html).toContain('class="badge other"');
      expect(html).toContain("in-sync"); // the raw legacy text is still shown, just unstyled
    });
  });
  it("shows a per-card summary count in the header area", () => {
    const html = renderDashboard([m], FIXED_NOW);
    expect(html).toContain("1 key — 1 present · 1 absent");
  });
  it("wraps the table in a horizontally-scrollable container and lets long key names wrap", () => {
    const html = renderDashboard([m], FIXED_NOW);
    expect(html).toContain('class="tablewrap"');
    expect(html).toContain('class="keyname"');
  });
});

describe("relativeTime", () => {
  it("renders minutes/hours/days ago", () => {
    expect(relativeTime(new Date(FIXED_NOW - 30_000).toISOString(), FIXED_NOW)).toBe("just now");
    expect(relativeTime(new Date(FIXED_NOW - 5 * 60_000).toISOString(), FIXED_NOW)).toBe("5m ago");
    expect(relativeTime(new Date(FIXED_NOW - 3 * 3_600_000).toISOString(), FIXED_NOW)).toBe("3h ago");
    expect(relativeTime(new Date(FIXED_NOW - 2 * 86_400_000).toISOString(), FIXED_NOW)).toBe("2d ago");
  });
  it("returns 'unknown' for an unparseable timestamp", () => {
    expect(relativeTime("not-a-date", FIXED_NOW)).toBe("unknown");
  });
});

describe("isStale", () => {
  it("is false just under 48h and true just over", () => {
    expect(isStale(new Date(FIXED_NOW - (48 * 3_600_000 - 1_000)).toISOString(), FIXED_NOW)).toBe(false);
    expect(isStale(new Date(FIXED_NOW - (48 * 3_600_000 + 1_000)).toISOString(), FIXED_NOW)).toBe(true);
  });
  it("is false for an unparseable timestamp (fail safe, not fail stale)", () => {
    expect(isStale("not-a-date", FIXED_NOW)).toBe(false);
  });
});

describe("generated_at rendering", () => {
  it("shows a relative-time string in the card header", () => {
    const recent: Manifest = { ...m, generated_at: new Date(FIXED_NOW - 5 * 60_000).toISOString() };
    const html = renderDashboard([recent], FIXED_NOW);
    expect(html).toContain("synced 5m ago");
  });
  it("flags a namespace stale after 48h with no new push", () => {
    const stale: Manifest = { ...m, generated_at: new Date(FIXED_NOW - 49 * 3_600_000).toISOString() };
    const html = renderDashboard([stale], FIXED_NOW);
    expect(html).toContain('class="badge stale"');
  });
  it("does not flag a fresh namespace as stale", () => {
    const fresh: Manifest = { ...m, generated_at: new Date(FIXED_NOW - 3_600_000).toISOString() };
    const html = renderDashboard([fresh], FIXED_NOW);
    expect(html).not.toContain('class="badge stale"');
  });
});

describe("renderLogin", () => {
  it("renders a password form", () => {
    const html = renderLogin();
    expect(html).toContain('name="password"');
    expect(html).toContain('action="/login"');
  });
  it("shows an error message when given one", () => {
    expect(renderLogin("wrong password")).toContain("wrong password");
  });
});

describe("renderLogin a11y", () => {
  it("has a label associated with the password input via id/for", () => {
    const html = renderLogin();
    expect(html).toContain('<label for="password"');
    expect(html).toContain('id="password"');
    expect(html).toContain('autocomplete="current-password"');
    expect(html).toContain('required');
    expect(html).not.toContain('aria-invalid');
  });
  it("marks the error message with role=alert and links input via aria-describedby when error is present", () => {
    const html = renderLogin("wrong password");
    expect(html).toContain('role="alert"');
    expect(html).toContain('id="login-error"');
    expect(html).toContain('aria-invalid="true"');
    expect(html).toContain('aria-describedby="login-error"');
  });
});

it("declares a favicon", () => {
  expect(renderDashboard([])).toContain('rel="icon"');
});

it("links back to the docs site in the footer", () => {
  expect(renderDashboard([])).toContain("skret.n24q02m.com");
});

it("offers a logout control on the dashboard", () => {
  const html = renderDashboard([m], FIXED_NOW);
  expect(html).toContain('action="/logout"');
});
