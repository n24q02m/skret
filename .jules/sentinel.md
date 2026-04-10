# Sentinel Learnings

## Data Handling in env command
- **Vulnerability**: Potential exposure of secrets if not handled carefully during formatting.
- **Learning**: Keeping data retrieval (`getEnvPairs`) separate from presentation (`printEnvPairs`) reduces the surface area for accidental logging or output of sensitive data during processing.
- **Prevention**: Ensure clear separation of concerns; use specific types like `envPair` to control what data is passed to formatting functions.
