# 🛡️ Sentinel: Security Assessments

## Security Learnings

### [CRITICAL] Time-of-Check to Time-of-Use (TOCTOU) in File Permissions
**Vulnerability:** Using `os.Chmod(path, mode)` after creating a file allows an attacker to replace the file with a symlink between creation and chmod, potentially leading to unauthorized permission changes on arbitrary files.
**Learning:** Always use `f.Chmod(mode)` on an open file descriptor (`*os.File`) instead of `os.Chmod(path, mode)`.
**Prevention:** Refactor all atomic write patterns to use `os.CreateTemp`, followed by `tmp.Chmod(mode)` on the returned file descriptor, before closing and renaming.

### [HIGH] Insecure Default Permissions on Sensitive Configuration
**Vulnerability:** Secret storage files and configuration files containing provider details were sometimes created with default `0644` permissions or relied on `os.WriteFile` which doesn't guarantee permissions if the file already exists.
**Learning:** Explicitly set `0600` permissions on all files containing secrets or sensitive configuration.
**Prevention:** Standardize on the atomic write pattern with explicit `Chmod(0o600)` on the file descriptor for all local file operations.
