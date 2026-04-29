## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-04-29 - [Route Status Messages to Stderr]
**Learning:** Routing CLI status updates, success messages, and user prompts to standard output (`stdout`) can inadvertently break shell data pipelines, particularly when users pipe data out (e.g. `skret env --format=dotenv > .env`).
**Action:** Always route operational output (success confirmations, status feedback, input prompts) to standard error (`stderr`) using methods like `cmd.PrintErrf` to reserve `stdout` exclusively for structured data.
