## 2025-05-18 - Friendly Empty States for List Commands
**Learning:** Returning an empty table header without context for an empty collection leaves users wondering if the command failed, path filtering was too aggressive, or the store is genuinely empty. A human-readable empty state improves command-line UX significantly.
**Action:** Replace empty table representations with actionable feedback (e.g., "No secrets found. Use 'skret set' to add one.") while maintaining structural integrity for programmatic outputs (like returning `[]` for JSON format).
