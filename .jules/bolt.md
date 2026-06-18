## 2025-04-27 - Optimize KeyToEnvName transformation
**Learning:** Multi-pass string transformations (like calling `strings.ReplaceAll` followed by `strings.ToUpper`) generate intermediate string allocations and put pressure on the Garbage Collector, particularly when invoked in a loop per-secret. Furthermore, for values that are already conformed (e.g., uppercase without `/`), any standard library string transformation often incurs unnecessary checks or duplication.
**Action:** Always employ a 'fast-path' check to bypass transformations and allocations when the input string already meets the desired output state. For ASCII strings that do require transformation, consolidate multi-pass operations into a single-pass loop utilizing `strings.Builder` and direct byte manipulation, while retaining a standard library fallback for multi-byte Unicode safety.

## 2024-04-24 - Extracting Invariant Operations out of Concurrent Synchronization Loops
**Learning:** In concurrent loops that process slice inputs to remote systems (e.g., sync loops that make API calls per secret), any invariant logic inside the loop causes unnecessary allocations and CPU overhead on each iteration (O(N) instead of O(1)). Base64-decoding a repository public key per-secret redundantly allocated slices and failed slowly.
**Action:** Always extract invariant parsing, decoding, or initialization operations outside concurrent loops. When an operation produces a structurally fixed type, such as an array like `[32]byte`, pass a pointer (e.g., `*[32]byte`) to the worker goroutines to safely prevent data races, guarantee constant memory usage during initialization, and improve parallel execution speed.

## 2026-05-07 - Log Redaction Performance and Scope
**Learning:** Using anchored regexes for secret redaction in logs is insufficient as it fails to catch secrets embedded within larger strings (e.g., error messages). However, global regex replacement is CPU-intensive. Safe fast-path checks, such as a minimum length requirement, can significantly reduce regex overhead for short, non-sensitive strings.
**Action:** Use global regex replacement for embedded secret redaction but always prefix it with a safe fast-path check (e.g., `len(val) < 5`) to bypass expensive evaluations for short values. Complement value-based redaction with key-based heuristic redaction for maximum safety.

## 2026-05-07 - Mitigating N+1 Queries in Bulk Imports
**Learning:** Sequential existence checks in loops (N+1 pattern) significantly degrade performance during bulk operations due to network latency overhead per secret.
**Action:** Implemented a tiered discovery approach (List -> GetBatch -> Get) and deduplicated input sets to minimize provider round-trips while maintaining operational resilience.

## 2026-05-07 - Implement OIDC-based Round-trip Secret Syncing in CI/CD
**Learning:** Migrating secrets from GitHub Secrets to cloud-native stores like AWS SSM without breaking existing workflows requires a "round-trip" synchronization strategy. By using OIDC for credential-free AWS access, CI workflows can safely fetch secrets from the cloud provider and sync them back to repository secrets as a pre-requisite step. This ensures that downstream actions relying on standard `${{ secrets.VAR }}` syntax remain functional while shifting the source of truth to the cloud store.
**Action:** In CI/CD pipelines, implement a synchronization job that uses OIDC and `skret sync --to=github` to refresh repository secrets from AWS SSM. Ensure this job has the necessary `id-token: write` and `secrets: write` permissions, and that subsequent deployment jobs depend on its completion.

## 2026-05-07 - Refactor Complex Conditional Logic into Named Helper Functions
**Learning:** Nested conditional checks within long loops (like the `auth status` iteration) reduce readability and can lead to logic errors where state is unintentionally overwritten (e.g., "expired" being masked by "invalid"). Extracting this logic into a small, focused helper function clarifies the priority of states and makes the core loop easier to maintain.
**Action:** Identify multi-state conditional blocks within loops and extract them into named helper functions (e.g., `getCredentialStatus`). This improves testability of the status logic itself and ensures a clean separation of concerns between data retrieval and display formatting.

## 2026-06-25 - Avoid String Function Overhead in Hot Loops
**Learning:** Functions like `strings.Cut` and `strings.Contains` provide a convenient API, but when used extensively in hot loops (such as parsing `KEY=VALUE` environment variables or scanning for a single delimiter like `$`), they incur measurable execution time overhead compared to lower-level operations.
**Action:** For single-byte searches in high-performance or frequently executed code paths, prefer `strings.IndexByte`. When splitting strings by a single character, use `strings.IndexByte` and manual slicing (e.g., `s[:idx]` and `s[idx+1:]`) instead of `strings.Cut`. This optimization reduces execution time and bypasses unnecessary standard library call overhead.

## 2024-04-27 - Optimize Local Provider Concurrency with RWMutex
**Learning:** For in-memory providers (like the local YAML provider), using a standard `sync.Mutex` for read operations (`Get`, `GetBatch`, `List`) causes unnecessary serialization of read requests. While it's not a remote I/O N+1 issue, it can become a bottleneck during high-concurrency read operations (e.g., multiple microservices or workers fetching secrets simultaneously).
**Action:** Replace `sync.Mutex` with `sync.RWMutex` in in-memory providers. Use `RLock` and `RUnlock` for all read-only operations to allow concurrent reads while still ensuring safe exclusive access for write operations (`Set`, `Delete`).

## 2024-04-27 - CI Patch Coverage Pitfall for Optimizations
**Learning:** Adding early returns or "fast-path" logic (like checking for empty input) creates new branches that must be explicitly covered by unit tests. Even if the overall package coverage is high, CI tools like Codecov often enforce a minimum "patch coverage" (e.g., 80-90% of the *new* lines must be hit), and missing a single branch in a small PR can cause CI to fail.
**Action:** When adding optimizations or early returns, immediately add a corresponding test case for that specific branch (e.g., passing an empty slice to a batch function) to ensure patch coverage requirements are met.

## 2026-10-27 - Hoist Slice Initialization
**Learning:** Initializing literal slices (e.g., `[]string{...}`) inside frequently executed functions dynamically allocates memory and initializes elements on every call, creating unnecessary overhead and GC pressure.
**Action:** Always hoist statically-defined slice literals out of function bodies into package-level variables to ensure they are allocated and initialized only once during program startup.

## 2024-05-31 - Escaping Closure Allocations in Resolving Dependency Cycles
**Learning:** In recursive dependency resolution loops, creating a `defer` closure inside the innermost loop execution path allocates memory unnecessarily on every invocation, especially if it only performs a simple boolean assignment like clearing a flag.
**Action:** Remove `defer` anonymous functions from hot recursive logic. Instead, structure the code to immediately execute the cleanup task locally in the same scope (e.g. `resolving[ref] = false` after expansion finishes) avoiding anonymous function allocations.

## 2026-06-25 - Skip Environment Resolution Logic on Empty Secrets
**Learning:** Functions that parse, resolve, and merge existing environment variables and secret maps often initialize deep variable-dependency graph structures and caches (maps) before they know if there's actual work to do.
**Action:** When a function accepts a slice or map of values to resolve (e.g., `BuildEnv(secrets ...)`), insert an early return (`if len(secrets) == 0 { return existingEnv }`) before initializing complex recursive expansion caches or looping over elements. This prevents unnecessary memory allocations in processes that invoke the code with no inputs.

## 2026-06-05 - Avoid Multi-Pass Strings ReplaceAll for ASCII String Sanitization
**Learning:** When sanitizing a string for a few specific ASCII characters (e.g., removing `\x00` and `\r`, replacing `\n` with space), executing multiple consecutive `strings.ReplaceAll` calls iterates over the string multiple times and creates unnecessary intermediate string allocations, slowing down performance.
**Action:** Use a fast-path check (`strings.ContainsAny`) to verify if work is needed. If true, process predominantly ASCII strings in a single pass using a pre-sized `strings.Builder` (via `b.Grow(len(val))`) and a byte-level loop with a `switch` statement, which completes the transformation with only one final string allocation.

## 2026-07-28 - Fast-path before string replacement
**Learning:** Functions like `strings.ReplaceAll` perform allocations or iterations even when the search string might be absent.
**Action:** Adding a fast path like `if strings.IndexByte(s, '"') == -1 { return s }` avoids this overhead when escaping values that rarely contain quotes.
## 2025-05-15 - Move slice early returns before slice/map initializations
**Learning:** Initializing maps or arrays in a function before checking early return conditions (e.g., `if len(input) == 0`) leads to unnecessary memory allocation and iteration overhead, especially if the function is frequently called with empty inputs or used in recursive paths.
**Action:** Always place early return checks at the very top of the function to avoid redundant memory allocations and logic executions.

## 2025-02-27 - Hoisting strings.NewReplacer
**Learning:** `strings.NewReplacer` allocates memory and builds internal tables upon initialization. In frequently invoked functions, this creates unnecessary overhead. Adding a fast-path check (`strings.ContainsAny`) to avoid replacements entirely in the common case yields ~10x performance improvement for clean strings.
**Action:** Always hoist `strings.NewReplacer` to package-level variables so they are initialized once, and use `strings.ContainsAny` for a fast-path early return when applicable.
