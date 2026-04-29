
## 2026-04-29 - [Logging] Redaction Bypass via Regex Anchors
**Vulnerability:** Secrets embedded within larger strings (like error messages or URLs) bypass redaction because the regular expressions use `^` and `$` anchors, requiring exact string matches.
**Learning:** Redaction filters should not assume secrets are isolated in their own string fields. They frequently leak inside other strings, requiring global replacement strategies (`ReplaceAllString`) instead of exact-match strategies.
**Prevention:** Remove start/end anchors (`^`, `$`) from secret detection regexes and use substring replacement instead of full-string replacement when performing redaction.
