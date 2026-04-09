## 2023-10-27 - O(N) Array Scan in Env Var Expansion
**Learning:** Found a performance bottleneck in `internal/exec/exec.go` where `os.Expand` did a linear scan of existing environment variables for every reference replacement. This is an $O(N \times M)$ operation (where $N$ is the number of secret variable substitutions and $M$ is the number of existing environment variables).
**Action:** Always check for linear array scans inside loops (like `os.Expand` or `.map()`). Replace them with $O(1)$ hash map lookups where the array isn't changing.
