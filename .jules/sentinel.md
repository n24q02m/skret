# Security Learnings

- **Vulnerability**: Potential resource exhaustion due to missing HTTP client timeouts.
- **Learning**: `http.DefaultClient` in Go has no timeout by default, which can lead to Goroutine leaks if a remote server hangs.
- **Prevention**: Always use a custom `http.Client` with an explicit `Timeout`.
