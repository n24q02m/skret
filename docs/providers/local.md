# Local YAML Provider

The local provider stores secrets in a plain YAML file. Designed for **development and testing only**.

## Configuration

```yaml
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
```

## File Format

```yaml
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/mydb"
  API_KEY: "dev-key-123"
  REDIS_URL: "redis://localhost:6379"
```

## Security

> **WARNING:** Local secrets files are NOT encrypted. Never use the local provider for production secrets.

- Always add `.secrets.*.yaml` to `.gitignore`
- The `skret init` command does this automatically
- File permissions are set to `0600` (owner read/write only)

## Capabilities

| Capability | Supported |
|-----------|-----------|
| Read | ✅ |
| Write | ✅ |
| Versioning | ❌ |
| Tagging | ❌ |
| Encryption | ❌ |
| Max value size | 1 MB |
