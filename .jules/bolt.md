## 2024-05-29 - [Optimized IsAuthError slice allocation]
**Learning:** Moving an inline array to a package-level variable might slow down micro-benchmarks by a few nanoseconds, but the real-world reduction in allocations and GC overhead is beneficial.
**Action:** Always move static, inline slices used in hot-paths to a package-level scope.
