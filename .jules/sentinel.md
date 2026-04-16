# Sentinel Learnings - HTTP Client Timeout

## Title: Resource Exhaustion via Default HTTP Client
## Vulnerability: Use of `http.DefaultClient` or clients without timeouts can lead to goroutine leaks and resource exhaustion if the remote server (e.g., GitHub API) hangs.
## Learning: While `GitHubSyncer` already had a 30s timeout, the audit correctly highlighted the importance of this pattern. Standardizing on `http.NoBody` instead of `nil` for bodyless requests is also a minor security best practice to prevent potential issues with some HTTP implementations.
## Prevention: Always initialize `http.Client` with an explicit `Timeout` and use `http.NewRequestWithContext` to ensure requests can be cancelled by the caller.

## Title: Stabilize CI for Go 1.26
## Vulnerability: Pre-built `golangci-lint` binaries may lag behind the latest Go versions, causing "can't load config" errors and preventing security scans.
## Learning: Building `golangci-lint` from source using `go install` ensures it is built with the project's Go version (1.26), resolving compatibility issues.
## Prevention: When using cutting-edge Go versions, prefer source-based installation of tooling in CI.
