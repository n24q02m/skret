## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-05-04 - [Routing Informational Messages to Stderr]
**Learning:** Routing informational messages such as "Deleted secret...", "Imported...", or "Logged out..." to `stderr` using `cmd.PrintErrf` or `cmd.PrintErrln` improves the programmatic experience without breaking pipelines. It enables the clean extraction of actual secret values or structured outputs from `stdout`, while keeping humans adequately informed on `stderr`.
**Action:** When printing informational, non-data messages to CLI output (e.g., status, confirmations), direct them to `stderr` rather than `stdout`.
## 2026-06-05 - [Empty States and Actionable Feedback for CLI Output]
**Learning:** When a CLI command returns an empty state (e.g., no configuration found, no history present), printing an actionable call-to-action (like "Use skret setup to initialize") to stderr significantly improves UX while preserving pipeline safety.
**Action:** Always add an actionable hint routed to stderr for empty states to help users understand their next step without polluting programmatic stdout.
