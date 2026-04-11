## 2026-04-11 - Support standard --force flag alongside --confirm
**Learning:** CLI users expect standard flags like `-f` / `--force` for destructive actions. Providing only custom flags (like `--confirm`) creates a frustrating UX, especially in scripts.
**Action:** Always include common aliases (like `-f` / `--force`) for destructive confirmation flags to align with established CLI conventions.
