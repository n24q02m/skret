# Security Learnings

## Resource Exhaustion via HTTP Timeouts
- **Vulnerability:** Use of `http.DefaultClient` which has no default timeout. This can lead to resource exhaustion if the remote server hangs or is extremely slow.
- **Learning:** Always use a custom `http.Client` with an explicit `Timeout`.
- **Prevention:** Avoid `http.DefaultClient.Do` and `http.Get/Post/etc.`. Initialize a client with a reasonable timeout (e.g., 30s) in the constructor of any struct that makes network requests.
