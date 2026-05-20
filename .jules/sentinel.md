## 2026-05-07 - Insufficient Redaction of Complex Secrets
**Vulnerability:** Secrets (tokens, passwords) were not redacted if they were embedded within larger strings (e.g., error messages) or if the attribute key name indicated sensitivity but the value didn't match a specific pattern.
**Learning:** Fixed-pattern matching at the start/end of a string is insufficient for log redaction. Heuristic key-based redaction and global regex replacement are necessary to catch secrets in varied contexts.
**Prevention:** Implement heuristic key-based redaction and use global regex replacement for secret patterns. Complement with a safe fast-path check for performance.

## 2026-05-07 - Prevent Command and Flag Injection in OpenBrowser
**Vulnerability:** The `OpenBrowser` function in `internal/auth/prompt.go` accepted unsanitized URLs, potentially allowing command and flag injection if a malicious URL (like `file:///etc/passwd` or an argument like `--help`) was passed.
**Learning:** Functions that execute system commands, like `exec.CommandContext`, are vulnerable to injection attacks if input is not validated and appropriately formatted. In macOS's `open` command, specifically, missing the argument separator (`--`) leaves it vulnerable to flag injection.
**Prevention:** Always validate URLs against expected schemas (e.g., `http` and `https`) before passing them to the system command. For commands like `open` on `darwin`, utilize the `--` separator to explicitly denote that the following values are arguments, not flags.

## 2026-05-07 - CSRF Vulnerability in Infisical PKCE Browser Flow
**Vulnerability:** Cross-Site Request Forgery (CSRF) in OAuth2 callback.
**Learning:** OAuth2 flows that use a loopback listener are still vulnerable to CSRF if they don't use and verify the `state` parameter. An attacker could potentially trick a user's browser into sending an authorization code to the user's own loopback listener, potentially linking the user's session to an attacker-controlled account or vice versa, depending on the flow.
**Prevention:** Always generate a cryptographically random `state` parameter at the beginning of the OAuth flow, include it in the authorization request, and verify it exactly in the callback handler before processing the authorization code.

## 2026-05-20 - Safe Remediation of CWE-22 (Path Traversal)
**Vulnerability:** A path traversal vulnerability existed in `internal/syncer/state.go`'s `StatePathFor` function. The `target` argument was concatenated directly into the string path without sanitization. Although other occurrences like reading config files flagged warnings due to dynamic path variables, substituting them with `os.OpenRoot` was not an effective mitigation when untrusted path inputs are merely evaluated relative to their own untrusted directories (`os.OpenRoot(filepath.Dir(untrustedPath))`).
**Learning:** `os.OpenRoot` is effective only when bounding file operations to a known, *trusted* base directory. Using `os.OpenRoot` dynamically with untrusted variables only results in "security theater". The most robust and simplest mitigation for dynamically constructed file paths containing untrusted variables is rigorous string sanitization of those specific input variables before path construction.
**Prevention:** For dynamically constructed paths involving untrusted segments, sanitize all user input components using a reliable sanitization function (e.g., stripping or replacing `../` and other control characters) before utilizing them to build the file path string. Use `os.OpenRoot` only when pinning operations to a statically defined or verified trusted directory.
