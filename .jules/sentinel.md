# Sentinel Security Learnings - skret

## Minimizing Provider API Surface
- **Vulnerability**: Indiscriminate API calls can lead to rate limiting (DoS) or increased exposure of access patterns.
- **Learning**: Batching operations like "list" instead of "get-in-a-loop" is not just a performance win but also a security best practice to reduce the footprint of the application on the secret provider.
- **Prevention**: Always check if a provider supports batch operations or listing before implementing per-resource checks in a loop.
