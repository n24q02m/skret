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
## $(date +%Y-%m-%d) - Strings Split vs Cut Loop (scope: validation vs allocation)
**Learning:** Replacing `strings.Split` with a manual `strings.Cut` loop is an excellent optimization for avoiding slice allocation when you only need to iterate over and validate path segments (e.g., `validStateManifestPath`). However, using a `strings.Cut` loop to manually `append` elements back into a slice (e.g., in `windowsStateManifestPathComponents`) is a pessimization. Go's native `strings.Split` is highly optimized to pre-calculate capacity and allocate the slice exactly once; manual `append` loops trigger multiple unnecessary internal array reallocations.
**Action:** Only replace `strings.Split` with `strings.Cut` loops if the resulting slice is no longer needed. If the function must ultimately return a slice of the segments, stick to `strings.Split` as it's the most efficient and readable way to achieve it.

## 2026-09-17 - Use strings.Cut instead of strings.Split for zero-allocation iteration
**Learning:** Using `strings.Split` for simple string parsing loops allocates a slice. If the function doesn't actually need to return or keep the slice, replacing `strings.Split` with `strings.Cut` within a loop eliminates the slice allocation.
**Action:** Always prefer `strings.Cut` in loops over `strings.Split` when validating or processing delimited strings where the resulting slice isn't needed or returned. This achieves zero-allocation performance without sacrificing maintainability.

## 2026-10-01 - Zero-allocation fast-path for string transformations
**Learning:** Functions that unconditionally transform strings using `strings.Builder` allocate memory on every call, even if the input requires no changes.
**Action:** When a transformation's happy path is to return the string unmodified (like environment variable names that are already uppercase), add a fast-path scan to check if mutations are needed first. Returning the original string directly drops allocations to zero.

## 2026-10-23 - Zero-allocation fast-path for case-insensitive string matching rejected due to security correctness
**Learning:** Replacing `strings.ToLower` combined with `strings.Contains` with a zero-allocation byte scanning loop can inadvertently break unicode case folding (e.g. U+212A KELVIN SIGN folding to "k"). When applied to security paths like redaction logic, missing a redaction case because of subtle unicode folding regressions is unacceptable, and manual byte-scans are often actually slower in wall time.
**Action:** Never attempt to hand-roll case-insensitive matching logic on security or redaction boundaries in an effort to save memory allocations. Rely on standard library implementations (like `strings.ToLower`) that correctly handle unicode edge cases, even if they allocate.
