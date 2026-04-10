# Security Learnings - skret

## Vulnerability: Indefinite Hangs / Resource Exhaustion
- **Learning**: Always use a custom `http.Client` with an explicit timeout (e.g., 30 seconds) instead of `http.DefaultClient`.
- **Prevention**: Use `&http.Client{Timeout: 30 * time.Second}` for all outbound requests.

## Vulnerability: Insecure Secret Storage
- **Learning**: Local secrets are stored in YAML files. These should be treated with appropriate file permissions (0600).
- **Prevention**: Ensure that generated or updated local secret files have restricted access.
