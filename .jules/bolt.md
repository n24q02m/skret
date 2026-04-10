# Optimization Learnings

- Replaced `http.DefaultClient` with a custom client containing a 30s timeout in `DopplerImporter`, `InfisicalImporter`, and `GitHubSyncer`. This prevents resource exhaustion and indefinite hangs in network operations.
- Downgraded Go version to 1.25 to maintain compatibility with `golangci-lint`.
