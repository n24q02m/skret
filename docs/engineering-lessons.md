# Engineering lessons

These entries were recovered from the working ledgers this repository kept at its root
until 2026-11-11: the notes of a discontinued automated assistant that proposed changes
under three remits -- performance (`bolt.md`), interface and accessibility
(`palette.md`) and security (`sentinel.md`). The entries are kept verbatim, each in the
shape it was written. The `**Commit:**` line under a heading names the commit that
landed that entry, so a settled question can be found in the repository history before
the same change is proposed again. A few entries quote the paths the ledgers occupied
before this move; those paths no longer exist.

# Performance (`bolt.md`)

## 2025-04-27 - Optimize KeyToEnvName transformation (done; do not revisit)

**Commit:** `4251b0c`

**Learning:** Multi-pass string transformations (like calling `strings.ReplaceAll` followed by `strings.ToUpper`) generate intermediate string allocations and put pressure on the Garbage Collector when invoked in a loop per-secret. `KeyToEnvName` was consolidated into a single-pass `strings.Builder` loop with direct byte manipulation, and that is its terminal state.
**Action:** For ASCII string sanitization, consolidate multi-pass operations into a single-pass loop utilizing `strings.Builder` and direct byte manipulation. Do NOT add a fast-path early return to `KeyToEnvName`: it is a cold path (once per secret per process, bounded by namespace size) and the saved allocation is dwarfed by the provider round-trip that fetched the secret. Seven such PRs were rejected (#504, #508, #518, #521, #523, #525, #526).

## 2025-04-27 - A fast-path needs a hot path and a benchmark

**Commit:** `4251b0c`

**Learning:** An early-return fast-path is only a win where the function is called often enough for the saved allocation to matter. Adding one to a per-secret or per-invocation function trades a real branch and a real test-coverage obligation for an unmeasurable gain, and the reviewer has no way to tell the difference without numbers.
**Action:** Before proposing a fast-path, confirm the function is on a hot path (called per-request, per-byte, or inside a loop over unbounded input) and include a `Benchmark*` in the PR showing the delta. `internal/exec/exec_perf_test.go` is where those benchmarks live. Without both, do not open the PR.

## 2024-04-24 - Extracting Invariant Operations out of Concurrent Synchronization Loops

**Commit:** `9dcde9d`

**Learning:** In concurrent loops that process slice inputs to remote systems (e.g., sync loops that make API calls per secret), any invariant logic inside the loop causes unnecessary allocations and CPU overhead on each iteration (O(N) instead of O(1)). Base64-decoding a repository public key per-secret redundantly allocated slices and failed slowly.
**Action:** Always extract invariant parsing, decoding, or initialization operations outside concurrent loops. When an operation produces a structurally fixed type, such as an array like `[32]byte`, pass a pointer (e.g., `*[32]byte`) to the worker goroutines to safely prevent data races, guarantee constant memory usage during initialization, and improve parallel execution speed.

## 2026-05-07 - Log Redaction Performance and Scope

**Commit:** `d8c940b`

**Learning:** Using anchored regexes for secret redaction in logs is insufficient as it fails to catch secrets embedded within larger strings (e.g., error messages). However, global regex replacement is CPU-intensive. Safe fast-path checks, such as a minimum length requirement, can significantly reduce regex overhead for short, non-sensitive strings.
**Action:** Use global regex replacement for embedded secret redaction but always prefix it with a safe fast-path check (e.g., `len(val) < 5`) to bypass expensive evaluations for short values. Complement value-based redaction with key-based heuristic redaction for maximum safety.

## 2026-05-07 - Mitigating N+1 Queries in Bulk Imports

**Commit:** `a4aa854`

**Learning:** Sequential existence checks in loops (N+1 pattern) significantly degrade performance during bulk operations due to network latency overhead per secret.
**Action:** Implemented a tiered discovery approach (List -> GetBatch -> Get) and deduplicated input sets to minimize provider round-trips while maintaining operational resilience.

## 2026-05-07 - Implement OIDC-based Round-trip Secret Syncing in CI/CD

**Commit:** `4732e41`

**Learning:** Migrating secrets from GitHub Secrets to cloud-native stores like AWS SSM without breaking existing workflows requires a "round-trip" synchronization strategy. By using OIDC for credential-free AWS access, CI workflows can safely fetch secrets from the cloud provider and sync them back to repository secrets as a pre-requisite step. This ensures that downstream actions relying on standard `${{ secrets.VAR }}` syntax remain functional while shifting the source of truth to the cloud store.
**Action:** In CI/CD pipelines, implement a synchronization job that uses OIDC and `skret sync --to=github` to refresh repository secrets from AWS SSM. Ensure this job has the necessary `id-token: write` and `secrets: write` permissions, and that subsequent deployment jobs depend on its completion.

## 2026-05-07 - Refactor Complex Conditional Logic into Named Helper Functions

**Commit:** `f38ad4f`

**Learning:** Nested conditional checks within long loops (like the `auth status` iteration) reduce readability and can lead to logic errors where state is unintentionally overwritten (e.g., "expired" being masked by "invalid"). Extracting this logic into a small, focused helper function clarifies the priority of states and makes the core loop easier to maintain.
**Action:** Identify multi-state conditional blocks within loops and extract them into named helper functions (e.g., `getCredentialStatus`). This improves testability of the status logic itself and ensures a clean separation of concerns between data retrieval and display formatting.

## 2026-06-25 - Avoid String Function Overhead in Hot Loops

**Commit:** `e246c66`

**Learning:** Functions like `strings.Cut` and `strings.Contains` provide a convenient API, but when used extensively in hot loops (such as parsing `KEY=VALUE` environment variables or scanning for a single delimiter like `$`), they incur measurable execution time overhead compared to lower-level operations.
**Action:** For single-byte searches in high-performance or frequently executed code paths, prefer `strings.IndexByte`. When splitting strings by a single character, use `strings.IndexByte` and manual slicing (e.g., `s[:idx]` and `s[idx+1:]`) instead of `strings.Cut`. This optimization reduces execution time and bypasses unnecessary standard library call overhead.

## 2024-04-27 - Optimize Local Provider Concurrency with RWMutex

**Commit:** `fa1ee56`

**Learning:** For in-memory providers (like the local YAML provider), using a standard `sync.Mutex` for read operations (`Get`, `GetBatch`, `List`) causes unnecessary serialization of read requests. While it's not a remote I/O N+1 issue, it can become a bottleneck during high-concurrency read operations (e.g., multiple microservices or workers fetching secrets simultaneously).
**Action:** Replace `sync.Mutex` with `sync.RWMutex` in in-memory providers. Use `RLock` and `RUnlock` for all read-only operations to allow concurrent reads while still ensuring safe exclusive access for write operations (`Set`, `Delete`).

## 2024-04-27 - CI Patch Coverage Pitfall for Optimizations

**Commit:** `fa1ee56`

**Learning:** Adding early returns or "fast-path" logic (like checking for empty input) creates new branches that must be explicitly covered by unit tests. Even if the overall package coverage is high, CI tools like Codecov often enforce a minimum "patch coverage" (e.g., 80-90% of the *new* lines must be hit), and missing a single branch in a small PR can cause CI to fail.
**Action:** When adding optimizations or early returns, immediately add a corresponding test case for that specific branch (e.g., passing an empty slice to a batch function) to ensure patch coverage requirements are met.

## 2026-10-27 - Hoist Slice Initialization

**Commit:** `4f4477f`

**Learning:** Initializing literal slices (e.g., `[]string{...}`) inside frequently executed functions dynamically allocates memory and initializes elements on every call, creating unnecessary overhead and GC pressure.
**Action:** Always hoist statically-defined slice literals out of function bodies into package-level variables to ensure they are allocated and initialized only once during program startup.

## 2024-05-31 - Escaping Closure Allocations in Resolving Dependency Cycles

**Commit:** `d78d158`

**Learning:** In recursive dependency resolution loops, creating a `defer` closure inside the innermost loop execution path allocates memory unnecessarily on every invocation, especially if it only performs a simple boolean assignment like clearing a flag.
**Action:** Remove `defer` anonymous functions from hot recursive logic. Instead, structure the code to immediately execute the cleanup task locally in the same scope (e.g. `resolving[ref] = false` after expansion finishes) avoiding anonymous function allocations.

## 2026-06-25 - Skip Environment Resolution Logic on Empty Secrets

**Commit:** `76b9621`

**Learning:** Functions that parse, resolve, and merge existing environment variables and secret maps often initialize deep variable-dependency graph structures and caches (maps) before they know if there's actual work to do.
**Action:** When a function accepts a slice or map of values to resolve (e.g., `BuildEnv(secrets ...)`), insert an early return (`if len(secrets) == 0 { return existingEnv }`) before initializing complex recursive expansion caches or looping over elements. This prevents unnecessary memory allocations in processes that invoke the code with no inputs.

## 2026-06-05 - Avoid Multi-Pass Strings ReplaceAll for ASCII String Sanitization

**Commit:** `a6e22bb`

**Learning:** When sanitizing a string for a few specific ASCII characters (e.g., removing `\x00` and `\r`, replacing `\n` with space), executing multiple consecutive `strings.ReplaceAll` calls iterates over the string multiple times and creates unnecessary intermediate string allocations, slowing down performance.
**Action:** Use a fast-path check (`strings.ContainsAny`) to verify if work is needed. If true, process predominantly ASCII strings in a single pass using a pre-sized `strings.Builder` (via `b.Grow(len(val))`) and a byte-level loop with a `switch` statement, which completes the transformation with only one final string allocation.

## 2026-07-28 - Fast-path before string replacement

**Commit:** `a5b2ced`

**Learning:** Functions like `strings.ReplaceAll` perform allocations or iterations even when the search string might be absent.
**Action:** Adding a fast path like `if strings.IndexByte(s, '"') == -1 { return s }` avoids this overhead when escaping values that rarely contain quotes.

## 2025-05-15 - Move slice early returns before slice/map initializations

**Commit:** `6a81edc`

**Learning:** Initializing maps or arrays in a function before checking early return conditions (e.g., `if len(input) == 0`) leads to unnecessary memory allocation and iteration overhead, especially if the function is frequently called with empty inputs or used in recursive paths.
**Action:** Always place early return checks at the very top of the function to avoid redundant memory allocations and logic executions.

## 2026-07-14 - Replacing strings.SplitN with strings.Cut

**Commit:** `215a6ad`

**Learning:** Functions like `strings.SplitN(s, delim, 2)` provide a convenient API, but when used to split strings by a single character or string, they incur measurable memory allocation overhead because they return a slice. Replacing them with `strings.Cut(s, delim)` avoids the heap allocation of the slice, providing a measurable performance improvement (zero allocations) while maintaining readability.
**Action:** Always prefer `strings.Cut` over `strings.SplitN(s, delim, 2)` when splitting a string into exactly two parts.

## 2026-08-03 - Single-pass HTML escaping on hot paths (scope: hot paths only)

**Commit:** `5f56090`

**Learning:** Chained `String.prototype.replace()` calls for HTML escaping create multiple intermediate string allocations, significantly impacting performance on rendering hot paths in the Cloudflare Workers environment. `esc()` in `hub/src/render.ts` qualifies: it runs once per key, per target and per namespace on every dashboard render. Its single-pass form is the terminal state.
**Action:** Replace chained `.replace()` calls with a single-pass regular expression and a dictionary map lookup (e.g., `s.replace(/[...]/g, (m) => map[m] || m)`) **only where the function runs per-request or inside a loop over unbounded input, and attach a measurement to the PR** (a `vitest bench` or a timed loop over representative input). A rewrite proposed without a number and without naming the hot path is a style change, not an optimization, and will be closed.

## 2026-08-08 - Base64URL helpers in hub/src/auth.ts are a cold path (done; do not revisit)

**Commit:** `5f56090`

**Learning:** `b64urlEncode` and `b64urlDecode` each execute exactly once per session mint and once per session verify -- a handful of calls per login, not per request and not inside a loop. The chained `.replace()` calls they use are already correct, and the trailing-padding strip (`.replace(/=+$/, "")`) is deliberately its own step so that padding is only removed from the tail rather than from anywhere in the string.
**Action:** Treat these two functions as settled. Two PRs proposing the single-pass rewrite here were closed on 2026-08-08 (#636, #639) because neither carried a measurement and neither call site is hot; #639 additionally widened the contract by folding the padding character into the character class. If a future change touches base64url, the win must be shown with a benchmark first.

## 2026-08-08 - An early return must not jump over a safety guard

**Commit:** `5f56090`

**Learning:** `syncer.FilterAbsent` deliberately fails when the target cannot enumerate its existing secrets, because the caller must treat that as fatal rather than silently overwriting. Placing `if len(secrets) == 0 { return }` above that check moves a correctness guard behind an input-size condition: a target misconfigured for `no_overwrite` would then pass silently on an empty sync instead of surfacing the error. PR #632 was closed on 2026-08-08 for exactly this.
**Action:** When adding an early return, first read what the code above it is protecting. Place the early return **after** any assertion, capability check, or validation whose failure the caller depends on -- and pair it with a `Benchmark*` showing the saved work, per the fast-path rule above.

## 2026-08-04 - Skip Map Initialization on Empty Secrets in DetectEnvNameCollisions (scope: that one function; done)

**Commit:** `393a2cd`

**Learning:** When `DetectEnvNameCollisions` is called with an empty list of secrets, the function would still unnecessarily allocate a map for `excludeSet` and check constraints before realizing there were no secrets to process. The early return there is measured (~73 ns/op to ~3 ns/op) and is the terminal state for that function.
**Action:** Treat this as specific to `DetectEnvNameCollisions`, not as a pattern to spread. PR #655 generalised it to `filterExcluded`, `SyncState.FilterUnchanged` and `SyncState.Update` and was closed on 2026-08-09, because in those three the saving is not there: `LoadSyncState` always hands back a non-nil `Hashes` map (state.go:82 and state.go:91-93), so `Update`'s map init is already unreachable in production, and `make([]T, 0, 0)` does not heap-allocate, so `FilterUnchanged`'s guard saves nothing while changing its return from an empty slice to nil. Before adding an empty-input guard anywhere else, show that the skipped work is a real allocation on a hot path and attach a `Benchmark*`, per the fast-path rule above.

## $(date +%Y-%m-%d) - Strings Split vs Cut Loop (scope: validation vs allocation)

**Commit:** `09732c7`

**Learning:** Replacing `strings.Split` with a manual `strings.Cut` loop is an excellent optimization for avoiding slice allocation when you only need to iterate over and validate path segments (e.g., `validStateManifestPath`). However, using a `strings.Cut` loop to manually `append` elements back into a slice (e.g., in `windowsStateManifestPathComponents`) is a pessimization. Go's native `strings.Split` is highly optimized to pre-calculate capacity and allocate the slice exactly once; manual `append` loops trigger multiple unnecessary internal array reallocations.
**Action:** Only replace `strings.Split` with `strings.Cut` loops if the resulting slice is no longer needed. If the function must ultimately return a slice of the segments, stick to `strings.Split` as it's the most efficient and readable way to achieve it.

## 2026-09-17 - Use strings.Cut instead of strings.Split for zero-allocation iteration

**Commit:** `06c9e3e`

**Learning:** Using `strings.Split` for simple string parsing loops allocates a slice. If the function doesn't actually need to return or keep the slice, replacing `strings.Split` with `strings.Cut` within a loop eliminates the slice allocation.
**Action:** Always prefer `strings.Cut` in loops over `strings.Split` when validating or processing delimited strings where the resulting slice isn't needed or returned. This achieves zero-allocation performance without sacrificing maintainability.

## 2026-10-01 - Zero-allocation fast-path for string transformations

**Commit:** `8849689`

**Learning:** Functions that unconditionally transform strings using `strings.Builder` allocate memory on every call, even if the input requires no changes.
**Action:** When a transformation's happy path is to return the string unmodified (like environment variable names that are already uppercase), add a fast-path scan to check if mutations are needed first. Returning the original string directly drops allocations to zero.

# Interface and accessibility (`palette.md`)

## 2025-04-26 - [Empty States for CLI Output]

**Commit:** `4e52458`

**Learning:** Returning a literal empty array `[]` for JSON format requests on empty lists ensures programmatic parsers won't fail, but displaying actionable user feedback (like 'No secrets found. Use skret set...') natively to standard error handles the human-readable empty states better without breaking pipelines.
**Action:** When printing lists to CLI output, distinguish machine-readable formats (e.g. JSON) that require strict typing, from human-readable formats that benefit from empty-state instructions routed via stderr.

## 2025-05-04 - [Routing Informational Messages to Stderr]

**Commit:** `ceda977`

**Learning:** Routing informational messages such as "Deleted secret...", "Imported...", or "Logged out..." to `stderr` using `cmd.PrintErrf` or `cmd.PrintErrln` improves the programmatic experience without breaking pipelines. It enables the clean extraction of actual secret values or structured outputs from `stdout`, while keeping humans adequately informed on `stderr`.
**Action:** When printing informational, non-data messages to CLI output (e.g., status, confirmations), direct them to `stderr` rather than `stdout`.

## 2026-06-05 - [Empty States and Actionable Feedback for CLI Output]

**Commit:** `e9d3172`

**Learning:** When a CLI command returns an empty state (e.g., no configuration found, no history present), printing an actionable call-to-action (like "Use skret setup to initialize") to stderr significantly improves UX while preserving pipeline safety.
**Action:** Always add an actionable hint routed to stderr for empty states to help users understand their next step without polluting programmatic stdout.

## 2025-05-18 - [CLI Tabular Output with Values]

**Commit:** `5b261c5`

**Learning:** When users request secret values using a `--values` flag alongside a tabular output format, they expect the values to be seamlessly integrated as a new column in the table, rather than having the flag silently ignored or requiring a switch to a less readable format like JSON.
**Action:** Always ensure that CLI formatting options (like `--values`) apply meaningfully across all compatible output formats (e.g., adding a `VALUE` column to the default `tabwriter` output in `list.go`), maintaining a consistent and expected user experience.

## 2025-06-05 - [Sync Command Empty State]

**Commit:** `ac83414`

**Learning:** Adding an empty state check with an actionable message (e.g., "No secrets found to sync. Use 'skret set' to add a secret.") directly after retrieving the secret list improves UX without breaking normal sync flow or preventing sync targets from clearing out.
**Action:** Always provide actionable error messages or empty state messages in CLI output before executing operations that act upon collections.

## 2025-06-27 - [Dynamic TUI Keybind Descriptions]

**Commit:** `dd23185`

**Learning:** In interactive TUIs built with bubbletea, static keybind descriptions in the footer can cause confusion if the action toggles state (e.g. "enter reveal" when the secret is already revealed).
**Action:** Ensure keybind descriptions dynamically reflect the action that will occur based on the current state (e.g. toggling between "enter reveal" and "enter hide") to set correct user expectations.

## 2026-06-29 - [Actionable Empty States]

**Commit:** `af3dfe8`

**Learning:** Returning an empty state for a TUI without an actionable message causes a poor UX where the application opens a blank UI or exits silently. The check should happen before the UI is initialized and provide clear guidance.
**Action:** When a TUI application would otherwise launch with empty data, intercept this state before UI initialization and print a clear, actionable error message to stderr.

## 2026-06-30 - [Contextual Keybind Hiding in Empty States]

**Commit:** `dc335a0`

**Learning:** When a list filter returns zero results, displaying contextual keybinds (e.g., "enter reveal") that depend on a selected item is confusing and sets false expectations, as pressing the key does nothing.
**Action:** Always conditionally render contextual keybind hints so they only appear when an item is actually selected, leaving only global actions (like navigation or quitting) visible during empty states.

## 2026-07-08 - [Empty States for CLI Commands Comparing Contexts]

**Commit:** `56b1829`

**Learning:** When a CLI command (like `diff`) compares two empty contexts, outputting "no drift" and "0 same" technically works but is confusing since there's no data. Printing a clear empty state message (e.g. "No secrets found to compare on either side.") explicitly surfaces the lack of data and sets correct user expectations.
**Action:** Always intercept zero-data comparisons in comparison or diff commands to output a clear empty state message before rendering standard diff output elements like matching counts.

## 2026-07-09 - [CLI Actionable Feedback for Missing Secrets]

**Commit:** `ef8562c`

**Learning:** When a command like `skret get <KEY>` fails because the secret does not exist, simply returning a standard error obscures the solution. Providing an actionable hint on standard error (e.g., `Secret not found. Use 'skret set <KEY> <value>' to create it.`) dramatically improves user experience and matches behavior in other parts of the system.
**Action:** Always intercept `ErrNotFound` states when retrieving individual items and print an actionable call-to-action to stderr before exiting.

## 2026-07-15 - TUI Contextual Keybind Hints

**Commit:** `9f56eab`

**Learning:** In Bubble Tea TUIs, standard footer keybind hints can remain visible during specialized states like filtering, leading to user confusion since standard navigation keys (up/down/enter to reveal) stop functioning normally.
**Action:** Always check the current component state (e.g., `m.list.FilterState() == list.Filtering`) in the `View()` function and update the footer to display the contextually correct keybinds (e.g., 'esc cancel - enter confirm filter') to set accurate expectations.

## 2026-07-15 - [Conventional Commits with Persona Prefix]

**Commit:** `9f56eab`

**Learning:** The PR Title lint check enforces Conventional Commits (`feat:`, `fix:`, `perf:`). If a persona prefix like `🎨 Palette:` is used as the primary prefix, the CI will fail.
**Action:** Always nest the persona prefix inside the conventional commit prefix, e.g., `feat: 🎨 palette: add keybind hints`. Ensure both the PR title and the commit message are updated to trigger the CI rerun successfully.

## 2026-07-23 - [Form Accessibility with ARIA Attributes]

**Commit:** `7ee9d26`

**Learning:** Adding `required` alongside dynamically updating `aria-invalid` and `aria-describedby` when errors occur in HTML forms significantly improves screen reader accessibility without changing core logic.
**Action:** Always add native validation attributes and dynamically set ARIA attributes to properly associate error states with form inputs in string templates.

## 2026-07-24 - Improve Empty State & Table Accessibility

**Commit:** `9636485`

**Learning:** When displaying complex data in tables, adding `scope="col"` to table headers significantly improves screen reader navigation. Empty states should also provide clear, structured formatting with actionable instructions rather than a single unbroken sentence.
**Action:** Ensure all future UI tables use proper semantic scoping and empty states utilize rich formatting (e.g., `<p>`, `<strong>`) for better readability and guidance.

## 2026-07-31 - [Time Element Semantics]

**Commit:** `d6b86a7`

**Learning:** When rendering relative timestamps in HTML, generic `<span>` elements lack machine readability. Using semantic `<time>` elements with `datetime` and `title` attributes makes the time machine-readable and natively exposes the absolute timestamp via browser tooltips without requiring custom UI components.
**Action:** Always replace generic span elements used for timestamps with semantic time tags (`<time datetime="..." title="...">`) in HTML templates.

## 2026-08-07 - [Form Errors in Document Titles] (shipped; do not re-propose for the login form)

**Commit:** `5f56090`

**Learning:** UX/Accessibility Pattern (Form Errors): Exposing form validation error states in the document `<title>` tag (e.g., prefixing the title with 'Error - ') in addition to using inline ARIA attributes ensures screen readers immediately announce the error state to the user upon page reload or form submission.
**Action:** Always expose form validation error states in the document `<title>` tag in addition to using inline ARIA attributes. For `hub/src/render.ts` this is already implemented: `page()` takes a `title` argument and `renderLogin()` passes `Error - skret vault` when an error is present, covered by a test asserting both branches. Four PRs proposed the same change (#633, #635, #640 -- #640 merged, the rest closed on 2026-08-08); the remaining opportunity is other forms, not this one.

## 2026-08-08 - [Empty States for Data Tables]

**Commit:** `5f56090`

**Learning:** A table rendered with a header row and an empty `<tbody>` is indistinguishable from a table whose data failed to load. A manifest can legitimately carry zero keys -- pushed before any secret was set, or emptied after deletions -- and the dashboard should say so.
**Action:** Render an empty-state row (`<td colspan="N" class="empty">`) whose colspan matches the column count declared in `thead`, with a heading plus the command that populates the table. Implemented for `renderNamespace` in `hub/src/render.ts`; the dashboard-level empty state (no manifests at all) already existed and is a separate case.

## 2026-10-01 - [Contextual ARIA Labels for Repeated UI Regions]

**Commit:** `6ceb81d`

**Learning:** When a UI contains multiple regions or elements of the same type (e.g., multiple scrollable tables), each element's `aria-label` must incorporate contextual data (like its corresponding namespace or environment) to uniquely identify it. Using identical, generic labels across multiple elements degrades the experience for screen reader users.
**Action:** Always dynamically generate `aria-label` attributes to include specific identifiers for iterative UI elements.

## 2026-10-06 - [Contextual Titles for Status Badges]

**Commit:** `3429d1e`

**Learning:** Using vague status badges (like "stale") without context can confuse users. Adding native `title` attributes to badges provides helpful tooltips on hover and additional context for screen readers without cluttering the UI.
**Action:** Always add descriptive `title` attributes to status badges that use jargon or ambiguous terms to explain their exact meaning.

## 2026-11-02 - [Visible Labels vs Placeholders]

**Commit:** `edac53a`

**Learning:** Relying solely on placeholders for input fields degrades the UX because the text disappears when users start typing, leaving them without context. Hiding labels with utility classes like `sr-only` exacerbates this issue for sighted users.
**Action:** Always provide visually persistent labels for form inputs instead of hiding them behind screen-reader-only classes, and avoid relying exclusively on placeholders for critical input context.

# Security (`sentinel.md`)

## 2026-05-07 - Insufficient Redaction of Complex Secrets

**Commit:** `d8c940b`

**Vulnerability:** Secrets (tokens, passwords) were not redacted if they were embedded within larger strings (e.g., error messages) or if the attribute key name indicated sensitivity but the value didn't match a specific pattern.
**Learning:** Fixed-pattern matching at the start/end of a string is insufficient for log redaction. Heuristic key-based redaction and global regex replacement are necessary to catch secrets in varied contexts.
**Prevention:** Implement heuristic key-based redaction and use global regex replacement for secret patterns. Complement with a safe fast-path check for performance.

## 2026-05-07 - Prevent Command and Flag Injection in OpenBrowser

**Commit:** `47ad859`

**Vulnerability:** The `OpenBrowser` function in `internal/auth/prompt.go` accepted unsanitized URLs, potentially allowing command and flag injection if a malicious URL (like `file:///etc/passwd` or an argument like `--help`) was passed.
**Learning:** Functions that execute system commands, like `exec.CommandContext`, are vulnerable to injection attacks if input is not validated and appropriately formatted. In macOS's `open` command, specifically, missing the argument separator (`--`) leaves it vulnerable to flag injection.
**Prevention:** Always validate URLs against expected schemas (e.g., `http` and `https`) before passing them to the system command. For commands like `open` on `darwin`, utilize the `--` separator to explicitly denote that the following values are arguments, not flags.

## 2026-05-07 - CSRF Vulnerability in Infisical PKCE Browser Flow

**Commit:** `cbb5a5c`

**Vulnerability:** Cross-Site Request Forgery (CSRF) in OAuth2 callback.
**Learning:** OAuth2 flows that use a loopback listener are still vulnerable to CSRF if they don't use and verify the `state` parameter. An attacker could potentially trick a user's browser into sending an authorization code to the user's own loopback listener, potentially linking the user's session to an attacker-controlled account or vice versa, depending on the flow.
**Prevention:** Always generate a cryptographically random `state` parameter at the beginning of the OAuth flow, include it in the authorization request, and verify it exactly in the callback handler before processing the authorization code.

## 2026-05-07 - Prevent Argument Injection in System Browser Commands

**Commit:** `c254db9`

**Vulnerability:** OS-level commands (like `open`, `xdg-open`, and `rundll32`) invoked via `exec.CommandContext` could be vulnerable to argument injection or unexpected flag execution when passed raw URL strings, even if those strings started with a valid scheme like HTTP or HTTPS.
**Learning:** Relying purely on scheme validation (`http`, `https`) is insufficient to prevent argument injection in shell-like commands if the rest of the string contains unescaped special characters or spaces.
**Prevention:** Sanitize user input by re-encoding URLs using `url.Parse` and `parsed.String()` before passing them to OS execution contexts. This normalizes the input and safely escapes characters that might otherwise be parsed as flags.

## 2026-05-28 - [SECURITY] Insecure HTTP Server Configuration

**Commit:** `6f82ca8`

Added `ReadTimeout` and `WriteTimeout` to `http.Server` in `internal/auth/infisical_browser.go` to prevent potential resource exhaustion on the local loopback listener.

## 2026-06-05 - Safe Shell Metacharacter Rejection

**Commit:** `651a312`

**Vulnerability:** URL command injection checks were incomplete. `OpenBrowser` rejected `$ ` and `;`, but allowed `|`, `<`, `>`, and backticks, which are also shell metacharacters capable of command injection.
**Learning:** When sanitizing arguments for shell-like execution (e.g., `xdg-open`), checking a narrow list of metacharacters is insufficient. However, blindly rejecting all special characters breaks legitimate URL functionality (e.g., `&` for query parameters, or `'` in query values).
**Prevention:** Use a refined blocklist: `strings.ContainsAny(safeURL, "|;<>` + "`" + `\\()$\"")`. Explicitly allow standard URL delimiters like `&` to preserve functionality while mitigating injection risks.

## 2026-06-05 - Avoid URL Injection via fmt.Sprintf

**Commit:** `f6e2b0f`

**Vulnerability:** URL strings constructed using `fmt.Sprintf` with user-supplied path segments or query parameters are vulnerable to URL injection and path traversal if the inputs contain unescaped characters.
**Learning:** Constructing complex URLs via string interpolation instead of relying on parsing libraries is a common source of injection flaws. `url.URL` handles URL-encoding natively, preserving intent without creating dangerous edge cases.
**Prevention:** Always use `net/url` to construct the URLs, utilizing functions like `url.Parse`, `url.JoinPath`, and `url.Values.Encode()` to properly escape path components and query parameters.

## 2025-02-23 - [Preventing DoS via http.DefaultClient and Malformed URL Injection]

**Commit:** `d6dc5ce`

**Vulnerability:** The application used `http.DefaultClient` in both production differ logic and test mock HTTP clients, making it susceptible to Denial of Service (DoS) attacks if an external endpoint hangs, keeping connections open indefinitely. The `fetchPage` function also unsafely appended query parameters (`?per_page=...`) using `fmt.Sprintf` directly onto a joined URL string, which can cause injection if `baseURL` ever contained a query.
**Learning:** `http.DefaultClient` lacks timeouts, which compromises process resilience when waiting on unreliable network components. Go's `url.JoinPath` safely constructs paths, but query string modification requires mutating `url.URL.RawQuery` using `url.Values{}` to guarantee parameters aren't malformed and that proper escaping occurs. Tests must also use configured clients to prevent test suite lockups during integration testing.
**Prevention:** Avoid `http.DefaultClient`. Always explicitly initialize an `&http.Client{Timeout: ...}`. Never mutate URLs via raw string concatenation `fmt.Sprintf("%s?x=y")`; instead, utilize `url.Parse`, `url.JoinPath`, and `Query().Set()` -> `Encode()`.

## 2026-06-29 - [SECURITY] URL Double-Escaping Injection in GitHub Provider

**Commit:** `dc31bcd`

**Vulnerability:** Constructing URLs by manually updating `url.URL.Path` with the result of `url.JoinPath(u.Path, ...)` caused path parameters to be double-escaped (e.g., spaces became `%2520`). This could lead to malformed requests or potentially bypass security filters if the backend decodes inconsistently.
**Learning:** In Go, `url.JoinPath` returns an already-escaped string. Assigning this back to `u.Path` causes `u.String()` to escape it again. The robust pattern is to use the `u.JoinPath(...)` method on the `*url.URL` object, which handles path segments safely and fluently without double-encoding.
**Prevention:** Always use the `JoinPath` method on `*url.URL` instead of the package-level function when building upon an existing parsed URL. Verify escaping behavior with tests using special characters in path segments.

## 2026-06-30 - Path Traversal Prevention in State File Paths

**Commit:** `a4412ca`

**Vulnerability:** A potential path traversal vulnerability where untrusted input (target, id) could be used to construct a sync state file path (`StatePathFor` in `internal/syncer/state.go`), potentially escaping the intended directory if not properly sanitized.
**Learning:** While the codebase uses a `sanitizeID` function to strip separators and `..`, relying solely on input sanitization for file paths is prone to edge cases if the sanitization logic is later updated or has missed cases.
**Prevention:** Add a defense-in-depth check using `filepath.Rel(baseDir, constructedPath)` to ensure the final resolved path strictly resides within the expected directory base and consists of exactly the expected filename, guaranteeing isolation regardless of the input.

## 2026-07-20 - Prevent malformed URL injection

**Commit:** `9a955f3`

**Vulnerability:** Raw string concatenation was used to construct API URLs from potentially untrusted base URLs, which can lead to malformed URL injection and escaping issues.
**Learning:** Using `url.Parse` and `url.URL.JoinPath()` prevents these issues by properly encoding path segments and preventing query string injection.
**Prevention:** Always use the `net/url` package to construct URLs, particularly when incorporating external input.

## 2026-07-26 - Add missing security headers

**Commit:** `39a35f5`

**Vulnerability:** Missing Strict-Transport-Security (HSTS) and X-Frame-Options headers on dashboard responses.
**Learning:** Even internal or simplified dashboards should implement defense in depth. Missing HSTS allows potential protocol downgrade attacks on subsequent visits, and missing X-Frame-Options opens the door for clickjacking attacks.
**Prevention:** Always include a comprehensive set of security headers (including HSTS and X-Frame-Options) in the shared middleware or common response headers configuration.

## 2026-08-06 - Fix Length Oracle Timing Attack in String Comparisons

**Commit:** `769a4a5`

**Vulnerability:** The `timingSafeEqualStr` function implemented a length check that exited early before performing a constant-time comparison on user-provided secrets. This creates a length oracle timing attack vulnerability where attackers can deduce the length of secrets.
**Learning:** Checking string lengths and exiting early avoids throwing exceptions in `timingSafeEqual` but exposes the secret's length via timing differences.
**Prevention:** Always hash both inputs (e.g., using SHA-256) before performing a constant-time comparison when dealing with potentially variable-length secrets. This ensures the comparison operates in constant time regardless of the original inputs' lengths.
