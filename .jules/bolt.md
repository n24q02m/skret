## 2025-04-27 - Optimize KeyToEnvName transformation (done; do not revisit)
**Learning:** Multi-pass string transformations (like calling `strings.ReplaceAll` followed by `strings.ToUpper`) generate intermediate string allocations and put pressure on the Garbage Collector when invoked in a loop per-secret. `KeyToEnvName` was consolidated into a single-pass `strings.Builder` loop with direct byte manipulation, and that is its terminal state.
**Action:** For ASCII string sanitization, consolidate multi-pass operations into a single-pass loop utilizing `strings.Builder` and direct byte manipulation. Do NOT add a fast-path early return to `KeyToEnvName`: it is a cold path (once per secret per process, bounded by namespace size) and the saved allocation is dwarfed by the provider round-trip that fetched the secret. Seven such PRs were rejected (#504, #508, #518, #521, #523, #525, #526).

## 2025-04-27 - A fast-path needs a hot path and a benchmark
**Learning:** An early-return fast-path is only a win where the function is called often enough for the saved allocation to matter. Adding one to a per-secret or per-invocation function trades a real branch and a real test-coverage obligation for an unmeasurable gain, and the reviewer has no way to tell the difference without numbers.
**Action:** Before proposing a fast-path, confirm the function is on a hot path (called per-request, per-byte, or inside a loop over unbounded input) and include a `Benchmark*` in the PR showing the delta. `internal/exec/exec_perf_test.go` is where those benchmarks live. Without both, do not open the PR.

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

## 2026-07-14 - Replacing strings.SplitN with strings.Cut
**Learning:** Functions like `strings.SplitN(s, delim, 2)` provide a convenient API, but when used to split strings by a single character or string, they incur measurable memory allocation overhead because they return a slice. Replacing them with `strings.Cut(s, delim)` avoids the heap allocation of the slice, providing a measurable performance improvement (zero allocations) while maintaining readability.
**Action:** Always prefer `strings.Cut` over `strings.SplitN(s, delim, 2)` when splitting a string into exactly two parts.

## 2026-08-03 - Single-pass HTML escaping on hot paths (scope: hot paths only)
**Learning:** Chained `String.prototype.replace()` calls for HTML escaping create multiple intermediate string allocations, significantly impacting performance on rendering hot paths in the Cloudflare Workers environment. `esc()` in `hub/src/render.ts` qualifies: it runs once per key, per target and per namespace on every dashboard render. Its single-pass form is the terminal state.
**Action:** Replace chained `.replace()` calls with a single-pass regular expression and a dictionary map lookup (e.g., `s.replace(/[...]/g, (m) => map[m] || m)`) **only where the function runs per-request or inside a loop over unbounded input, and attach a measurement to the PR** (a `vitest bench` or a timed loop over representative input). A rewrite proposed without a number and without naming the hot path is a style change, not an optimization, and will be closed.

## 2026-08-08 - Base64URL helpers in hub/src/auth.ts are a cold path (done; do not revisit)
**Learning:** `b64urlEncode` and `b64urlDecode` each execute exactly once per session mint and once per session verify -- a handful of calls per login, not per request and not inside a loop. The chained `.replace()` calls they use are already correct, and the trailing-padding strip (`.replace(/=+$/, "")`) is deliberately its own step so that padding is only removed from the tail rather than from anywhere in the string.
**Action:** Treat these two functions as settled. Two PRs proposing the single-pass rewrite here were closed on 2026-08-08 (#636, #639) because neither carried a measurement and neither call site is hot; #639 additionally widened the contract by folding the padding character into the character class. If a future change touches base64url, the win must be shown with a benchmark first.

## 2026-08-08 - An early return must not jump over a safety guard
**Learning:** `syncer.FilterAbsent` deliberately fails when the target cannot enumerate its existing secrets, because the caller must treat that as fatal rather than silently overwriting. Placing `if len(secrets) == 0 { return }` above that check moves a correctness guard behind an input-size condition: a target misconfigured for `no_overwrite` would then pass silently on an empty sync instead of surfacing the error. PR #632 was closed on 2026-08-08 for exactly this.
**Action:** When adding an early return, first read what the code above it is protecting. Place the early return **after** any assertion, capability check, or validation whose failure the caller depends on -- and pair it with a `Benchmark*` showing the saved work, per the fast-path rule above.

## 2026-08-04 - Skip Map Initialization on Empty Secrets in DetectEnvNameCollisions (scope: that one function; done)
**Learning:** When `DetectEnvNameCollisions` is called with an empty list of secrets, the function would still unnecessarily allocate a map for `excludeSet` and check constraints before realizing there were no secrets to process. The early return there is measured (~73 ns/op to ~3 ns/op) and is the terminal state for that function.
**Action:** Treat this as specific to `DetectEnvNameCollisions`, not as a pattern to spread. PR #655 generalised it to `filterExcluded`, `SyncState.FilterUnchanged` and `SyncState.Update` and was closed on 2026-08-09, because in those three the saving is not there: `LoadSyncState` always hands back a non-nil `Hashes` map (state.go:82 and state.go:91-93), so `Update`'s map init is already unreachable in production, and `make([]T, 0, 0)` does not heap-allocate, so `FilterUnchanged`'s guard saves nothing while changing its return from an empty slice to nil. Before adding an empty-input guard anywhere else, show that the skipped work is a real allocation on a hot path and attach a `Benchmark*`, per the fast-path rule above.
## 2026-08-22 - Removing Unreachable Code for Codecov Compliance
**Learning:** Adding defensive breaks like  at the end of a reverse-parsing loop can result in 0% hit rates in Codecov patch coverage if the code is mathematically unreachable. In , the segment starting at  always contains the drive letter and a colon, so the  check always fails and breaks the loop first, rendering the subsequent  dead code.
**Action:** When Codecov patch checks fail due to uncovered conditional logic, analyze the code mathematically. If a condition is impossible to reach due to preceding invariants, remove the unreachable code entirely instead of attempting to write tests for it, adhering to the Codecov Analysis workflow convention.
## $(date +%Y-%m-%d) - Removing Unreachable Code for Codecov Compliance
**Learning:** Adding defensive breaks like `if idx == -1 { break }` at the end of a reverse-parsing loop can result in 0% hit rates in Codecov patch coverage if the code is mathematically unreachable. In `config.ResolvePath`, the segment starting at `idx = -1` always contains the drive letter and a colon, so the `isSSMPathSegment(seg)` check always fails and breaks the loop first, rendering the subsequent `if idx == -1 { break }` dead code.
**Action:** When Codecov patch checks fail due to uncovered conditional logic, analyze the code mathematically. If a condition is impossible to reach due to preceding invariants, remove the unreachable code entirely instead of attempting to write tests for it, adhering to the Codecov Analysis workflow convention.
## 2026-08-22 - Removing Unreachable Code for Codecov Compliance
**Learning:** Adding defensive breaks like `if idx == -1 { break }` at the end of a reverse-parsing loop can result in 0% hit rates in Codecov patch coverage if the code is mathematically unreachable. In `config.ResolvePath`, the segment starting at `idx = -1` always contains the drive letter and a colon, so the `isSSMPathSegment(seg)` check always fails and breaks the loop first, rendering the subsequent `if idx == -1 { break }` dead code.
**Action:** When Codecov patch checks fail due to uncovered conditional logic, analyze the code mathematically. If a condition is impossible to reach due to preceding invariants, remove the unreachable code entirely instead of attempting to write tests for it, adhering to the Codecov Analysis workflow convention.
## 2026-08-22 - Removing Unreachable Code for Codecov Compliance
**Learning:** Adding defensive breaks like `if idx == -1 { break }` at the end of a reverse-parsing loop can result in 0% hit rates in Codecov patch coverage if the code is mathematically unreachable. In `config.ResolvePath`, the segment starting at `idx = -1` always contains the drive letter and a colon, so the `isSSMPathSegment(seg)` check always fails and breaks the loop first, rendering the subsequent `if idx == -1 { break }` dead code.
**Action:** When Codecov patch checks fail due to uncovered conditional logic, analyze the code mathematically. If a condition is impossible to reach due to preceding invariants, remove the unreachable code entirely instead of attempting to write tests for it, adhering to the Codecov Analysis workflow convention.
