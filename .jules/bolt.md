# Optimization & Codebase Learnings

## File Permission Management

- **Context:** The project manages sensitive secrets. File system permissions are a critical layer of security.
- **Learning:** `os.WriteFile` and `os.OpenFile` require explicit permission bits. `0o600` is the standard for private configuration/secret files.
- **Verification:** Verification of file permissions should be done via `os.Stat` and checking `info.Mode().Perm()`.
