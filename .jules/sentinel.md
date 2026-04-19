## 2026-04-19 - Prevent TOCTOU in local provider
**Vulnerability:** The local provider wrote secrets using a temporary file and did not explicitly restrict permissions on the file descriptor before closing and renaming it, allowing a Time-of-Check to Time-of-Use window where another user could potentially read or change the file contents.
**Learning:** Atomic file writes with temporary files require setting restrictive file permissions directly on the open file descriptor.
**Prevention:** Use `tmp.Chmod(0o600)` before closing the file to ensure restrictive permissions.
