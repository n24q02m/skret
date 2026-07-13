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
| 9 | Drift detected | Sets differ | `skret diff <A> <B> --exit-code` found a difference between the two sets |
| 10 | Leak found | Secret value in a tracked file | `skret scan` (or `--staged`) found a real secret value committed to a tracked file |
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
# Debug level -- shows configuration resolution (provider, path)
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

### Access denied (exit 3)

```
Error: AccessDeniedException: User: arn:aws:iam::123456789012:user/dev
is not authorized to perform: ssm:GetParameter
```

An IAM denial from AWS SSM surfaces as a provider error (exit 3) on write/list-path commands (`set`, `env`, `run`, `sync`, ...). `skret get` currently deviates -- any provider failure through `get`, including this `ssm:GetParameter` denial, surfaces as exit 5 (not found) instead.

**Fix:** Your IAM policy does not allow access to this path. Update the IAM policy to include the SSM path prefix. See [Authentication - IAM Policies](/guide/authentication#iam-policy-examples).

### Value too large (exit 3)

```
Error: validation: value size 5120 bytes exceeds maximum 4096 bytes for standard parameters
```

skret only ever writes AWS SSM Standard-tier parameters -- it never requests `Tier: Advanced` -- so the effective limit is 4 KB. A value over that limit fails with AWS's `ValidationException`, surfaced as a provider error (exit 3).

**Fix:** Options:

1. Reduce the secret value size
2. Split into multiple secrets
3. Use the [`local`](/providers/local/) provider for development, or a provider with a bigger cap (see [provider comparison](/providers/comparison/))

### Throttling (exit 3)

```
Error: ThrottlingException: Rate exceeded
```

AWS SSM has a 40 TPS limit for `GetParameter*` calls. skret configures the AWS SDK's adaptive-mode retryer with up to 10 attempts and a 20-second max backoff automatically; a `ThrottlingException` that persists past those retries surfaces as a provider error (exit 3).

**Fix:** If this persists:

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

## Windows: Git Bash / MSYS Path Mangling

If you run skret from Git Bash (or another MSYS2-based shell) on Windows, a
leading-slash key argument like `/myapp/prod/DATABASE_URL` (or a bare key
that skret qualifies into that shape) can get silently rewritten by the
shell's POSIX-path emulation into something like
`C:/Program Files/Git/myapp/prod/DATABASE_URL` before skret ever sees it —
Git Bash treats a leading `/` as a Unix root and expands it against its own
install path.

`skret get`, `set`, `delete`, `history`, and `rollback` all detect this: if
the resolved secret path prefix (e.g. `/myapp/prod`) shows up in the middle
of the mangled argument, skret recovers the intended key and prints:

```
warning: key looked shell-mangled; using "/myapp/prod/DATABASE_URL" (omit the leading slash, or set MSYS_NO_PATHCONV=1)
```

If you see this warning:

- The command still ran correctly — skret recovered the key you meant.
- To avoid the mangling (and the warning) entirely, either:
  - Omit the leading slash and pass a bare key (`skret get DATABASE_URL`) — skret qualifies it with the configured path itself, so the shell never sees a `/`-prefixed argument to rewrite.
  - Set `MSYS_NO_PATHCONV=1` for the command, which disables Git Bash's path conversion: `MSYS_NO_PATHCONV=1 skret get /myapp/prod/DATABASE_URL`.
  - Use PowerShell instead of Git Bash — PowerShell has no POSIX-path emulation, so this class of mangling cannot happen there.

This only affects command **arguments** (the key you pass to `get`/`set`/`delete`/`history`/`rollback`). It does not affect secret **values** — those are never touched by shell path expansion.

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
