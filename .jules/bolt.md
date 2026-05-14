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

## 2026-05-14 - Optimizing String Matching in Loops
**Learning:** Calling `strings.ToLower()` inside a loop on a dynamic string and against a set of static strings results in significant redundant allocations (O(N) vs O(1)).
**Action:** When performing case-insensitive string matching within a loop, hoist the `strings.ToLower` call for the dynamic string outside the loop and pre-lowercase the static list of strings.
Learning: The semantic PR action checks the PR title for 'fix:' or 'feat:' and fails if uppercase characters follow the colon. We need to submit with a lowercase title
