# Performance Optimizations

## Optimize Secret Key to Environment Variable Conversion
**Learning:** `strings.ReplaceAll` and `strings.ToUpper` both allocate new strings. When used together in a loop (e.g., `BuildEnv`), they create significant GC pressure. A manual single-pass loop using `strings.Builder` can avoid intermediate allocations. Additionally, adding a fast-path check to avoid `strings.Builder` entirely for already-conforming strings further improves performance on cold paths.
**Action:** Refactored `internal/exec/exec.go` to use a `transformToEnvName` helper with a single-pass loop and fast-path. Inlined prefix-stripping logic in `BuildEnv` to avoid redundant checks and function call overhead.
