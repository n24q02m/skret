
## 2024-05-24 - Logging Secret Leakage via Embedded Strings
**Vulnerability:** The secret redactor in `internal/logging/redact.go` failed to redact secrets when they were embedded within larger strings (e.g., URLs or error messages).
**Learning:** The regular expressions for redaction were anchored with `^` and `$`, meaning they only matched when the entire log field value consisted of the secret. Furthermore, the logic completely returned the secret string as-is instead of replacing occurrences within the string.
**Prevention:** Remove `^` and `$` anchors from redaction regexes, and always use global replacement functions (like `ReplaceAllString`) to ensure secrets embedded within sentences, URLs, or paths are properly scrubbed. Avoid exact-match anchors for redaction patterns unless explicitly intended.
