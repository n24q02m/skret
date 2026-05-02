## 2026-05-02 - Log Redaction Bypassed by Embedded Secrets
**Vulnerability:** Exact-match anchors (`^` and `$`) in secret redaction regex patterns failed to catch secrets embedded inside larger strings (e.g., error messages or URLs).
**Learning:** Returning a generic `[REDACTED]` string and using anchored regexes is ineffective for log redaction. If a sensitive value is part of a larger sentence or concatenated string, it won't match, causing a data leak.
**Prevention:** Remove exact-match anchors from secret regex patterns and use `ReplaceAllString` to scan and redact embedded secrets while preserving the surrounding context. Ensure query parameter regexes (like key-value pairs) terminate on ampersands (`[^\s&]+`) to prevent over-redacting subsequent parameters.
