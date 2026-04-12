## 2023-10-24 - Do Not Use http.DefaultClient
**Vulnerability:** Found uses of `http.DefaultClient` which has no explicit timeout, risking resource exhaustion.
**Learning:** The default HTTP client lacks a timeout configuration, making it vulnerable to denial-of-service or hangs if the server is slow or unresponsive.
**Prevention:** Always instantiate a custom `http.Client` with an explicit timeout (e.g., `Timeout: 30 * time.Second`).
## 2024-04-12 - Explicit Permissions on Temporary Files
**Vulnerability:** In `internal/provider/local/local.go`, the temporary file generated during the `Set` atomic write process (`os.CreateTemp`) was not explicitly setting `0600` permissions. While `os.CreateTemp` on Unix natively sets `0600`, OS or deployment nuances can bypass it.
**Learning:** For atomic saves containing sensitive credentials, failing to explicitly invoke `os.Chmod(tmpPath, 0600)` immediately prior to an `os.Rename` exposes files to incorrect default configurations or permission drift, risking unauthenticated local read/write (CWE-732).
**Prevention:** Always pair `os.CreateTemp` atomic writes with an explicit `os.Chmod(file.Name(), 0600)` for strictly secret-containing files before invoking `os.Rename`.
