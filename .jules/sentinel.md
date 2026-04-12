# Sentinel Learnings

## Data Handling in env command
- **Vulnerability**: Potential exposure of secrets if not handled carefully during formatting.
- **Learning**: Keeping data retrieval (`getEnvPairs`) separate from presentation (`printEnvPairs`) reduces the surface area for accidental logging or output of sensitive data during processing.
- **Prevention**: Ensure clear separation of concerns; use specific types like `envPair` to control what data is passed to formatting functions.

## Secure Marshaling
- **Vulnerability**: Unhandled marshaling errors could lead to silent failures or partial data leaks.
- **Learning**: Always check for errors when marshaling sensitive data structures (JSON/YAML) to ensure the integrity and completeness of the output.
- **Prevention**: Added explicit error checks and structured error returns using `skret.NewError`.
