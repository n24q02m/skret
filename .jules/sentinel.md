# Sentinel Security Learnings - skret

- **Vulnerability**: Potential exposure of sensitive tokens in logs or command history if passed as CLI arguments.
- **Learning**: Always prefer environment variables for sensitive tokens (e.g., `DOPPLER_TOKEN`, `INFISICAL_TOKEN`).
- **Prevention**: The `createImporter` method retrieves tokens from environment variables, ensuring they are not part of the command flags.
