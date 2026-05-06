## 2025-04-26 - [Empty States for CLI Output]
**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-04-27 - [CLI Output Streams for DX]
**Learning:** Redirecting CLI informational messages, prompts, and success confirmations to `stderr` is crucial for good Developer Experience (DX). It keeps `stdout` clean for purely parsable data. However, be careful not to redirect primary tabular output data (e.g. `auth status`) that users may rely on piping, which should remain on `stdout`.
**Action:** When working on CLI tools, review `cmd.Printf` usage and convert status/informational texts to `cmd.PrintErrf` to prevent polluting standard output pipelines, whilst keeping actual payload data on standard output.
