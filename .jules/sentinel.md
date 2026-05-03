
## 2024-05-03 - Embedded Secrets Logging Bypassing Redaction
**Vulnerability:** Key-value secrets (e.g. `token=secret`) and static patterns (e.g. `sk-000...`) embedded inside larger text like URL query strings or error messages completely bypassed the log redaction filter.
**Learning:** This existed because the `secretPatterns` regex configurations used exact-match anchors (`^` and `$`). If an exact match failed on an embedded sub-string, it returned false and printed the raw message.
**Prevention:** Remove `^` and `$` exact match regex anchors for secret redaction where values can be embedded. Use substring substitution instead of binary matching on entire strings, explicitly isolate query strings parameters ending with ampersands, and leverage string-based substitution logic.
