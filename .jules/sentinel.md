## 2025-04-10 - Missing HTTP Timeouts
**Vulnerability:** External HTTP requests (GitHub, Doppler, Infisical) were using `http.DefaultClient` which has no timeout by default.
**Learning:** In Go, `http.DefaultClient` allows requests to hang indefinitely if the external service fails to respond or is slow. This can cause the CLI or service to stall completely, leading to resource exhaustion (e.g. holding up go routines or process handles indefinitely).
**Prevention:** Always use a custom `http.Client` with an explicit `Timeout` (e.g., `&http.Client{Timeout: 30 * time.Second}`) for all outbound network requests.
