---
title: Troubleshooting
description: "skret uses structured exit codes to indicate the type of failure:"
---

## Exit Codes

skret uses structured exit codes to indicate the type of failure:

| Code | Name | Description | Common Cause |
|------|------|-------------|-------------|
| 0 | Success | Operation completed | -- |
| 1 | Generic error | Unclassified failure | Unexpected runtime error |
| 2 | Config error | Configuration problem | `.skret.yaml` not found, invalid schema |
| 3 | Provider error | Backend failure | AWS SSM unreachable, API error |
| 4 | Auth error | Authentication failed | Missing/expired AWS credentials |
| 5 | Not found | Secret does not exist | Wrong key name or path |
| 6 | Conflict error | Resource conflict | Key already exists (with `--on-conflict=fail`) |
| 7 | Network error | Connectivity issue | No internet, DNS failure, timeout |
| 8 | Validation error | Invalid input | Value exceeds 4 KB limit, bad key format |
| 125 | Exec error | Process execution failed | Command not found in `skret run --` |

Check exit codes in scripts:

```bash
skret get DATABASE_URL
echo "Exit code: $?"

# Or handle specifically
if ! skret run -- make up-app; then
  echo "skret failed with code $?"
fi
```

## Debug Logging

Enable verbose output with `SKRET_LOG`:

```bash
# Debug level -- shows config resolution, API calls, timing
SKRET_LOG=debug skret list

# JSON format for structured log parsing
SKRET_LOG=debug SKRET_LOG_FORMAT=json skret get DATABASE_URL
```

Log levels: `debug`, `info` (default), `warn`, `error`.

Logs go to **stderr**, command output goes to **stdout**. This means you can safely pipe output:

```bash
# Logs visible on stderr, only the secret value on stdout
SKRET_LOG=debug skret get DATABASE_URL > secret.txt
```

## Common Errors

### `.skret.yaml` not found (exit 2)

```
Error: failed to discover configuration: .skret.yaml not found
```

**Fix:** Run `skret init` in your project root, or ensure `.skret.yaml` exists somewhere between your current directory and the git root.

```bash
skret init --provider=aws --path=/myapp/prod --region=us-east-1
```

### Invalid config schema (exit 2)

```
Error: config: unsupported version "2" (expected "1")
```

**Fix:** Check `.skret.yaml` syntax. The `version` field must be `"1"`.

### No environment specified (exit 2)

```
Error: resolve: no environment specified (use --env or set default_env)
```

**Fix:** Either set `default_env` in `.skret.yaml` or pass `--env`:

```bash
skret --env=prod list
```

### AWS credentials not found (exit 4)

```
Error: failed to initialize provider "aws": no valid credential sources found
```

**Fix:** Ensure AWS credentials are available. Check:

```bash
# Verify credentials are configured
aws sts get-caller-identity

# Or set environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

See [Authentication](/guide/authentication) for all credential methods.

### Secret not found (exit 5)

```
Error: failed to get secret "DATABASE_URL": secret not found
```

**Fix:** Verify the secret exists under the configured path:

```bash
# List all secrets to see what's available
skret list

# Check you're using the right environment
skret --env=prod list
```

### Access denied (exit 4)

```
Error: AccessDeniedException: User: arn:aws:iam::123456789012:user/dev
is not authorized to perform: ssm:GetParameter
```

**Fix:** Your IAM policy does not allow access to this path. Update the IAM policy to include the SSM path prefix. See [Authentication - IAM Policies](/guide/authentication#iam-policy-examples).

### Value too large (exit 8)

```
Error: validation: value size 5120 bytes exceeds maximum 4096 bytes for standard parameters
```

**Fix:** AWS SSM Standard parameters have a 4 KB limit. Options:

1. Reduce the secret value size
2. Split into multiple secrets
3. Use Advanced parameters (cost: $0.05/month per parameter)

### Throttling (exit 7)

```
Error: ThrottlingException: Rate exceeded
```

**Fix:** AWS SSM has a 40 TPS limit for `GetParameter*` calls. skret retries with exponential backoff automatically. If this persists:

1. Reduce concurrent calls
2. Use `skret run --` (single batch call) instead of individual `skret get` calls
3. Request a quota increase in AWS Service Quotas

### Command not found in `skret run` (exit 125)

```
Error: exec: "mycommand": executable file not found in $PATH
```

**Fix:** Ensure the command exists and is in your `PATH`:

```bash
which mycommand
skret run -- /full/path/to/mycommand
```

## Environment Variable Conflicts

skret merges secrets into the existing environment. Existing env vars take precedence over secrets from the provider. This is intentional (user control).

To debug which values are being injected:

```bash
# See all secrets that would be injected (dotenv format)
skret env

# Compare with current environment
skret env | sort > /tmp/skret-secrets.txt
env | sort > /tmp/current-env.txt
diff /tmp/skret-secrets.txt /tmp/current-env.txt
```

## Reporting Issues

If you encounter an unexpected error:

1. Run with `SKRET_LOG=debug` and capture the full output
2. Check the exit code
3. Open an issue at [github.com/n24q02m/skret/issues](https://github.com/n24q02m/skret/issues) with the debug log (redact any secret values)
