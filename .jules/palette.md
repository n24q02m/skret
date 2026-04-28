## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-04-28 - [Route Status Messages to Stderr]
**Learning:** Informational outputs, prompts, and success messages sent to stdout can pollute data pipelines and break scripts when commands are chained (e.g. `skret set ... > out.txt`).
**Action:** Send all human-readable status, success messages, and empty state feedback to standard error (`stderr`), reserving standard output (`stdout`) purely for machine-readable data and expected payload output.
