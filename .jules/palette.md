## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-05-04 - [Routing Informational Messages to Stderr]
**Learning:** Routing informational messages such as "Deleted secret...", "Imported...", or "Logged out..." to `stderr` using `cmd.PrintErrf` or `cmd.PrintErrln` improves the programmatic experience without breaking pipelines. It enables the clean extraction of actual secret values or structured outputs from `stdout`, while keeping humans adequately informed on `stderr`.
**Action:** When printing informational, non-data messages to CLI output (e.g., status, confirmations), direct them to `stderr` rather than `stdout`.
## 2026-06-05 - [Empty States and Actionable Feedback for CLI Output]
**Learning:** When a CLI command returns an empty state (e.g., no configuration found, no history present), printing an actionable call-to-action (like "Use skret setup to initialize") to stderr significantly improves UX while preserving pipeline safety.
**Action:** Always add an actionable hint routed to stderr for empty states to help users understand their next step without polluting programmatic stdout.

## 2025-05-18 - [CLI Tabular Output with Values]
**Learning:** When users request secret values using a `--values` flag alongside a tabular output format, they expect the values to be seamlessly integrated as a new column in the table, rather than having the flag silently ignored or requiring a switch to a less readable format like JSON.
**Action:** Always ensure that CLI formatting options (like `--values`) apply meaningfully across all compatible output formats (e.g., adding a `VALUE` column to the default `tabwriter` output in `list.go`), maintaining a consistent and expected user experience.
## 2025-06-05 - [Sync Command Empty State]
**Learning:** Adding an empty state check with an actionable message (e.g., "No secrets found to sync. Use 'skret set' to add a secret.") directly after retrieving the secret list improves UX without breaking normal sync flow or preventing sync targets from clearing out.
**Action:** Always provide actionable error messages or empty state messages in CLI output before executing operations that act upon collections.

## 2025-06-27 - [Dynamic TUI Keybind Descriptions]
**Learning:** In interactive TUIs built with bubbletea, static keybind descriptions in the footer can cause confusion if the action toggles state (e.g. "enter reveal" when the secret is already revealed).
**Action:** Ensure keybind descriptions dynamically reflect the action that will occur based on the current state (e.g. toggling between "enter reveal" and "enter hide") to set correct user expectations.

## 2026-06-29 - Improved Error Actionability (Bug E)
**Learning:** Error messages that only list remedies without explaining the underlying requirement can be confusing. A structured "Requirement -> Problem -> Remedy" flow is more self-explanatory.
**Action:** Updated `configNotFoundMsg` in `internal/cli/helpers.go` to explicitly state that skret requires configuration for resolution before listing setup/init/path remedies.
