# Bolt Learnings - GitHub Syncer Cleanup

## Title: Data Race in GitHub Syncer Tests
## Learning: Existing tests for GitHubSyncer in `syncer_test.go` and `syncer_comprehensive_test.go` had data races because they shared integer counters (`putCalls`, `getKeyCalls`) across concurrent HTTP requests in `httptest.NewServer` without proper synchronization (mutexes).
## Action: Wrapped the counter increments and switch logic in the mock HTTP handlers with `sync.Mutex` to ensure thread-safety during `go test -race` execution.

## Title: Standardized Error Handling for Body Reads
## Learning: Following project conventions, HTTP response body reads should always handle errors from `io.ReadAll` and wrap them with descriptive context including the status code.
## Action: Updated `getPublicKey` and `putSecret` in `internal/syncer/github.go` to check for and wrap errors from `io.ReadAll`.

## Title: Extract Invariant Operations from GitHub Syncer Loop
## Learning: Performing base64 decoding of the repository public key inside the concurrent processing loop caused redundant O(N) memory allocations and CPU overhead.
## Action: Moved the decoding of the public key outside the loop in `Sync`, refactoring `putSecret` and `sealSecret` to accept the pre-decoded `[32]byte` key.
