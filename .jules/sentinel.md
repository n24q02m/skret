# Security Learnings

## Insecure File Permissions on Generated Configuration

**Vulnerability:** The `skret init` command was creating the `.skret.yaml` configuration file with `0o644` (world-readable) permissions. Since this file can contain sensitive information or point to sensitive local secret files, it should be restricted to the owner.

**Learning:** Always use restrictive permissions (e.g., `0o600`) when creating configuration files or data files that might contain or reference sensitive information.

**Prevention:**
- Default to `0o600` for all file creations unless there is a specific reason for the file to be world-readable.
- Use `os.CreateTemp` when possible as it defaults to restrictive permissions.
- Audit `os.WriteFile` and `os.OpenFile` calls for appropriate permission bits.
