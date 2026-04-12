# Security Learnings

## HTTP Client Timeouts
- **Vulnerability**: Indefinite hangs and resource exhaustion due to use of `http.DefaultClient` which has no timeout.
- **Learning**: Always use a custom `http.Client` with an explicit timeout for all network operations.
- **Prevention**: Configured `GitHubSyncer` with a dedicated `http.Client` having a 30-second timeout.
