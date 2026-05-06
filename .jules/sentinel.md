## 2026-05-06 - Fix embedded secret leak in logs
**Vulnerability:** Embedded secrets within larger strings (e.g. error messages like "failed with token=ghp_...") and log `Message` values were not redacted.
**Learning:** The `secretPatterns` used exact-match regex anchors (`^` and `$`), which bypassed redaction for embedded secrets. Additionally, only log `Attrs` were redacted, skipping the main `Message` text.
**Prevention:** Remove `^` and `$` anchors to enable substring matching. Update key-value regex patterns (e.g., `((?:password|secret|token|key)=)[^\s&]+`) to avoid over-redacting query strings. Apply redaction logic directly to both the `Message` and string attributes, using minimum string length checks as an optimization.
