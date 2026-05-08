## 2026-05-07 - Insufficient Redaction of Complex Secrets
**Vulnerability:** Secrets (tokens, passwords) were not redacted if they were embedded within larger strings (e.g., error messages) or if the attribute key name indicated sensitivity but the value didn't match a specific pattern.
**Learning:** Fixed-pattern matching at the start/end of a string is insufficient for log redaction. Heuristic key-based redaction and global regex replacement are necessary to catch secrets in varied contexts.
**Prevention:** Implement heuristic key-based redaction and use global regex replacement for secret patterns. Complement with a safe fast-path check for performance.
