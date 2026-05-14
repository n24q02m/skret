## 2024-05-14 - Empty States in CLI tools
**Learning:** For command line tools that output structured data (JSON/YAML), "empty states" must output the correct empty structure (e.g., `[]` or `{}`) to `stdout` to avoid breaking machine parsers, while helpful human-readable guidance (like "No secrets found. Use...") should be routed to `stderr`.
**Action:** Next time working on a CLI, separate human feedback from machine data using stdout and stderr properly.
