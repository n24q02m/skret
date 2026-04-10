# Codebase Learnings - skret

- Architecture: Follows a pattern of 'Importers' (internal/importer) for sourcing secrets and 'Syncers' (internal/syncer) for distributing them.
- Configuration: Uses `.skret.yaml` for environment-specific settings (provider, path, etc.).
- Providers: `local` and `aws` are currently supported. The `pkg/skret.Client` is a wrapper around these providers.
- Testing: Prefers table-driven tests and `testify/assert`. Mocking providers is the best way to test the high-level API.
