1. **Analyze GitHub Syncer Performance**: `GitHubSyncer.Sync` decodes the repository public key from base64 into bytes inside `sealSecret` for every single secret. This results in O(N) duplicate decodings and memory allocations for the same public key.
2. **Optimize `github.go`**:
   - Add early return if `len(secrets) == 0`.
   - Deduplicate incoming secrets by `s.Key` (or destination name) before processing to avoid redundant network calls.
   - Extract the public key base64 decoding into `Sync` so it only occurs once.
   - Change `putSecret` and `sealSecret` to accept a read-only pointer `*[32]byte` representing the parsed recipient public key.
3. **Verify Functionality**: Run `go test ./...` to ensure these performance optimizations do not introduce bugs or regressions.
4. **Pre Commit Steps**: Run `pre_commit_instructions` to test, verify, and document before commit.
5. **Submit Change**: Create PR with a summary of the performance impact.
