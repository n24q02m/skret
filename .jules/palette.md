## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-05-01 - [Empty States for CLI Commands Output]
**Learning:** Returning an empty response and routing informational or empty state strings (like 'No secrets found') to standard error (`stderr`) avoids cluttering or breaking automation when tools use stdout for pipe-chaining (`skret env > .env`).
**Action:** When printing lists or environments from commands, ensure all human-readable feedback messages (warnings, empties, "No history") bypass standard output so data streams are clean.
