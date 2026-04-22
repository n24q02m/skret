## 2025-04-22 - Optimize String Transformations in KeyToEnvName
**Learning:** Combining multi-pass string manipulations (`strings.ReplaceAll` followed by `strings.ToUpper`) into a single-pass loop with a `strings.Builder` and a fast-path bypass reduces memory allocations and execution time, especially when the majority of strings require no changes.
**Action:** When performing multiple string transformations within a critical path or loop, check if a fast-path bypass is applicable, and if not, use a single-pass `strings.Builder` approach to avoid intermediate string allocations.
