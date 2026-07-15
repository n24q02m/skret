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
## 2026-06-29 - [Actionable Empty States]
**Learning:** Returning an empty state for a TUI without an actionable message causes a poor UX where the application opens a blank UI or exits silently. The check should happen before the UI is initialized and provide clear guidance.
**Action:** When a TUI application would otherwise launch with empty data, intercept this state before UI initialization and print a clear, actionable error message to stderr.

## 2026-06-30 - [Contextual Keybind Hiding in Empty States]
**Learning:** When a list filter returns zero results, displaying contextual keybinds (e.g., "enter reveal") that depend on a selected item is confusing and sets false expectations, as pressing the key does nothing.
**Action:** Always conditionally render contextual keybind hints so they only appear when an item is actually selected, leaving only global actions (like navigation or quitting) visible during empty states.

## 2026-07-08 - [Empty States for CLI Commands Comparing Contexts]
**Learning:** When a CLI command (like `diff`) compares two empty contexts, outputting "no drift" and "0 same" technically works but is confusing since there's no data. Printing a clear empty state message (e.g. "No secrets found to compare on either side.") explicitly surfaces the lack of data and sets correct user expectations.
**Action:** Always intercept zero-data comparisons in comparison or diff commands to output a clear empty state message before rendering standard diff output elements like matching counts.

## 2026-07-09 - [CLI Actionable Feedback for Missing Secrets]
**Learning:** When a command like `skret get <KEY>` fails because the secret does not exist, simply returning a standard error obscures the solution. Providing an actionable hint on standard error (e.g., `Secret not found. Use 'skret set <KEY> <value>' to create it.`) dramatically improves user experience and matches behavior in other parts of the system.
**Action:** Always intercept `ErrNotFound` states when retrieving individual items and print an actionable call-to-action to stderr before exiting.
## $(date +%Y-%m-%d) - TUI Contextual Keybind Hints
**Learning:** In Bubble Tea TUIs, standard footer keybind hints can remain visible during specialized states like filtering, leading to user confusion since standard navigation keys (up/down/enter to reveal) stop functioning normally.
**Action:** Always check the current component state (e.g., `m.list.FilterState() == list.Filtering`) in the `View()` function and update the footer to display the contextually correct keybinds (e.g., 'esc cancel - enter confirm filter') to set accurate expectations.
