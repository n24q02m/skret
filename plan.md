1. **Identify the vulnerability:** In `internal/cli/hub.go`, the `postManifest` function constructs the target URL using raw string concatenation: `hubURL+"/api/manifest"`. This is vulnerable to malformed URL injection if `hubURL` contains query parameters (e.g., `http://example.com?foo=bar` becomes `http://example.com?foo=bar/api/manifest`). The sentinel memory notes: "Never mutate URLs via raw string concatenation `fmt.Sprintf("%s?x=y")`; instead, utilize `url.Parse`, `url.JoinPath`".
2. **Implement the fix:**
   - Parse `hubURL` using `url.Parse(hubURL)`. If it fails, return an error.
   - Use the `u.JoinPath("/api/manifest")` method (as memory dictates to use method `JoinPath` on the parsed `url.URL` instead of package level `url.JoinPath`).
   - Use `u.String()` as the target URL for `http.NewRequestWithContext`.
3. **Verify the fix:** Run `go test ./internal/cli` to verify no regressions.
4. **Complete pre-commit steps:** Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
5. **Submit PR:** Submit the change with the required PR title format `🛡️ Sentinel: [CRITICAL/HIGH] Fix [vulnerability type]` and required description format containing `🚨 Severity:`, `💡 Vulnerability:`, `🎯 Impact:`, `🔧 Fix:`, and `✅ Verification:`.
