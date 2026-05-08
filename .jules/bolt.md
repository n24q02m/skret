## 2025-04-27 - Optimize KeyToEnvName transformation
**Learning:** Multi-pass string transformations (like calling `strings.ReplaceAll` followed by `strings.ToUpper`) generate intermediate string allocations and put pressure on the Garbage Collector, particularly when invoked in a loop per-secret. Furthermore, for values that are already conformed (e.g., uppercase without `/`), any standard library string transformation often incurs unnecessary checks or duplication.
**Action:** Always employ a 'fast-path' check to bypass transformations and allocations when the input string already meets the desired output state. For ASCII strings that do require transformation, consolidate multi-pass operations into a single-pass loop utilizing `strings.Builder` and direct byte manipulation, while retaining a standard library fallback for multi-byte Unicode safety.

## 2024-04-24 - Extracting Invariant Operations out of Concurrent Synchronization Loops
**Learning:** In concurrent loops that process slice inputs to remote systems (e.g., sync loops that make API calls per secret), any invariant logic inside the loop causes unnecessary allocations and CPU overhead on each iteration (O(N) instead of O(1)). Base64-decoding a repository public key per-secret redundantly allocated slices and failed slowly.
**Action:** Always extract invariant parsing, decoding, or initialization operations outside concurrent loops. When an operation produces a structurally fixed type, such as an array like `[32]byte`, pass a pointer (e.g., `*[32]byte`) to the worker goroutines to safely prevent data races, guarantee constant memory usage during initialization, and improve parallel execution speed.

## 2026-05-03 - Log Redaction Fast Path
**Learning:** Running multiple complex regular expressions on every logged string is unnecessarily expensive, especially since many log values (like "id", "true", "ok", or short numbers) are too short to possibly contain the secrets we're looking for. The codebase handles this by using a length requirement (`len(val) < 5`) as an absolute minimum fast path to skip regex evaluations.
**Action:** Always implement a length-based fast path check to bypass expensive regex evaluation for strings under the minimum threshold. This improves performance for general operations without missing actual secrets.

## 2026-05-03 - Semantic PR Title Requirement
**Learning:** The CI pipeline enforces semantic pull request titles using `amannn/action-semantic-pull-request`. My previous PR title "⚡ Bolt: Add fast path..." failed this check because it lacked a valid prefix (like `feat:` or `fix:`). The correct format required by the AGENTS.md constraints for the Bolt persona is `feat: ⚡ bolt: [performance improvement]`.
**Action:** Always format PR titles with the `feat: ` or `fix: ` prefix before the persona emoji and name to pass CI semantic release checks.
