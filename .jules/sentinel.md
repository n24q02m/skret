## 2023-10-24 - Do Not Use http.DefaultClient
**Vulnerability:** Found uses of `http.DefaultClient` which has no explicit timeout, risking resource exhaustion.
**Learning:** The default HTTP client lacks a timeout configuration, making it vulnerable to denial-of-service or hangs if the server is slow or unresponsive.
**Prevention:** Always instantiate a custom `http.Client` with an explicit timeout (e.g., `Timeout: 30 * time.Second`).
