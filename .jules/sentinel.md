# Sentinel Security Learnings

## Vulnerability
Missing HTTP client timeout when using `http.DefaultClient`.

## Learning
In Go, `http.DefaultClient` is used by default for many HTTP operations, but it has no timeout. This means that if a remote server hangs or is extremely slow, the request can stay open indefinitely, leading to resource exhaustion (goroutine leakage, file descriptor exhaustion) and potential denial of service for the application.

## Prevention
Always use a custom `http.Client` with an explicit, reasonable timeout (e.g., 30 seconds) instead of relying on `http.DefaultClient`. This ensures that requests are terminated if they take too long, protecting the application's stability and resources.
