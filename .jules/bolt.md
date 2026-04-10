# Bolt Optimization Learnings - skret

## Batch Conflict Detection in Import
- **Optimization**: Replaced N individual `p.Get` calls with a single `p.List` call before the import loop.
- **Why**: Reduces the "N+1 Problem" where the number of network requests grows linearly with the number of imported secrets.
- **Implementation**:
  - Used `p.List(ctx, prefix)` to fetch existing secrets.
  - Stored keys in a `map[string]struct{}` for O(1) lookup.
  - Added fallback to `p.Get` if `p.List` fails, ensuring robustness if the provider has restrictive permissions.
- **Impact**: Significant performance improvement for large imports (e.g., hundreds of secrets) and reduced API usage/cost.
