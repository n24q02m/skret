## 2024-04-23 - Empty State for Secrets List
**Learning:** Returning no output when listing an empty collection creates a confusing experience. Programmatic consumers (e.g., json format) expect empty collections `[]`, while human users expect actionable feedback rather than a blank screen.
**Action:** Added a friendly, actionable empty state message ("No secrets found. Use 'skret set' to add one.") for default/table output, while preserving `[]` for JSON format. This aligns with standard CLI UX patterns.
