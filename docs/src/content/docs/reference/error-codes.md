---
title: Error Codes
description: "skret uses structured exit codes to communicate failure types. Every error includes a machine-readable code and a human-readable message on stderr."
---

skret uses structured exit codes to communicate failure types. Every error includes a machine-readable code and a human-readable message on stderr.

## Exit Code Table

| Code | Constant | Meaning | Remediation |
|------|----------|---------|-------------|
| 0 | `ExitSuccess` | Operation completed successfully | -- |
| 1 | `ExitGenericError` | Unclassified error | Check the error message. File a bug if unexpected. |
| 2 | `ExitConfigError` | Configuration problem | Verify `.skret.yaml` exists, has valid syntax, and `version: "1"`. Run `skret init` if missing. |
| 3 | `ExitProviderError` | Backend provider failure | Check provider connectivity. For AWS: verify region, check SSM service status. |
| 4 | `ExitAuthError` | Authentication failed | Verify credentials. For AWS: run `aws sts get-caller-identity`. Check IAM policy grants SSM access to the path. |
| 5 | `ExitNotFoundError` | Secret does not exist | Verify the key name with `skret list`. Check you are targeting the correct environment (`--env`). |
| 6 | `ExitConflictError` | Resource conflict | Key already exists when using `--on-conflict=fail`. Use `--on-conflict=overwrite` or `--on-conflict=skip`. |
| 7 | `ExitNetworkError` | Network/connectivity failure | Check internet connection, DNS resolution, and firewall rules. For AWS: verify VPC endpoints if in a private subnet. |
| 8 | `ExitValidationError` | Input validation failed | Check value size (4 KB limit for SSM Standard), key format, and required fields. |
| 125 | `ExitExecError` | Process execution error | The command passed to `skret run --` could not be executed. Verify the command exists in `$PATH`. |

## Error Structure

Errors from the `pkg/skret` library are typed as `*skret.Error`:

```go
type Error struct {
    Code    int    // Exit code from the table above
    Message string // Human-readable description
    Err     error  // Wrapped underlying error
}
```

Extract the exit code programmatically:

```go
import "github.com/n24q02m/skret/pkg/skret"

client, err := skret.New()
if err != nil {
    code := skret.ExitCode(err) // Returns the structured exit code
    fmt.Fprintf(os.Stderr, "exit %d: %v\n", code, err)
    os.Exit(code)
}
```

## Scripting with Exit Codes

```bash
#!/bin/bash
set -e

skret get DATABASE_URL > /dev/null 2>&1
code=$?

case $code in
  0) echo "Secret exists" ;;
  2) echo "Config error -- run skret init" ;;
  4) echo "Auth error -- check AWS credentials" ;;
  5) echo "Secret not found" ;;
  *) echo "Unexpected error (code $code)" ;;
esac
```

## Provider-Specific Errors

### AWS SSM

| AWS Error | skret Code | Description |
|-----------|-----------|-------------|
| `ParameterNotFound` | 5 | Secret key does not exist at the given path |
| `AccessDeniedException` | 4 | IAM policy denies the operation |
| `ThrottlingException` | 7 | API rate limit exceeded (40 TPS default) |
| `ValidationException` | 8 | Invalid parameter name or value too large |
| `InternalServerError` | 3 | AWS service error |

skret automatically retries `ThrottlingException` with exponential backoff (up to 3 retries) before returning the error.

## Debug Output

For any error, enable debug logging to see the full context:

```bash
SKRET_LOG=debug skret get MY_SECRET
```

This prints config resolution steps, API calls, and timing to stderr without exposing secret values.
