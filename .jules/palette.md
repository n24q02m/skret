## 2023-10-27 - [List Empty State]
**Learning:** Returning actionable empty states ("No secrets found. Use 'skret set' to create one.") instead of empty table headers provides better user guidance in CLI tools, while maintaining structured formats like `[]` for JSON output ensures programmatic parsers don't break.
**Action:** Always check array lengths before rendering list outputs and provide human-readable guidance for empty states unless formatting as JSON.
