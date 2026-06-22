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
## 2026-05-07 - Prevent Argument Injection in System Browser Commands
**Vulnerability:** OS-level commands (like `open`, `xdg-open`, and `rundll32`) invoked via `exec.CommandContext` could be vulnerable to argument injection or unexpected flag execution when passed raw URL strings, even if those strings started with a valid scheme like HTTP or HTTPS.
**Learning:** Relying purely on scheme validation (`http`, `https`) is insufficient to prevent argument injection in shell-like commands if the rest of the string contains unescaped special characters or spaces.
**Prevention:** Sanitize user input by re-encoding URLs using `url.Parse` and `parsed.String()` before passing them to OS execution contexts. This normalizes the input and safely escapes characters that might otherwise be parsed as flags.

## 2026-05-28 - [SECURITY] Insecure HTTP Server Configuration

Added `ReadTimeout` and `WriteTimeout` to `http.Server` in `internal/auth/infisical_browser.go` to prevent potential resource exhaustion on the local loopback listener.

## 2026-06-05 - Safe Shell Metacharacter Rejection
**Vulnerability:** URL command injection checks were incomplete. `OpenBrowser` rejected `$ ` and `;`, but allowed `|`, `<`, `>`, and backticks, which are also shell metacharacters capable of command injection.
**Learning:** When sanitizing arguments for shell-like execution (e.g., `xdg-open`), checking a narrow list of metacharacters is insufficient. However, blindly rejecting all special characters breaks legitimate URL functionality (e.g., `&` for query parameters, or `'` in query values).
**Prevention:** Use a refined blocklist: `strings.ContainsAny(safeURL, "|;<>` + "`" + `\\()$\"")`. Explicitly allow standard URL delimiters like `&` to preserve functionality while mitigating injection risks.

## 2026-06-05 - Avoid URL Injection via fmt.Sprintf
**Vulnerability:** URL strings constructed using `fmt.Sprintf` with user-supplied path segments or query parameters are vulnerable to URL injection and path traversal if the inputs contain unescaped characters.
**Learning:** Constructing complex URLs via string interpolation instead of relying on parsing libraries is a common source of injection flaws. `url.URL` handles URL-encoding natively, preserving intent without creating dangerous edge cases.
**Prevention:** Always use `net/url` to construct the URLs, utilizing functions like `url.Parse`, `url.JoinPath`, and `url.Values.Encode()` to properly escape path components and query parameters.

## 2026-06-10 - DoS via Default HTTP Client
**Vulnerability:** The use of `http.DefaultClient` without an explicit timeout leaves the application vulnerable to Denial-of-Service (DoS) if an external server hangs indefinitely.
**Learning:** Default HTTP clients in Go do not have timeouts. This can cause network calls to block forever, exhausting resources.
**Prevention:** Always initialize a custom `http.Client` with an explicit `Timeout` (e.g., `&http.Client{Timeout: 30 * time.Second}`).
