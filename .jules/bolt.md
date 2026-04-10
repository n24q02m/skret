# Learnings

- Testing unexported functions in Go can be done by creating a test file in the same package (e.g., `errors_internal_test.go` in `package aws`).
- Table-driven tests are effective for testing pure functions with multiple input cases like error mapping.

- If CI fails with `golangci-lint` exit code 3 due to Go version mismatch (`the Go language version (go1.24) used to build golangci-lint is lower than the targeted Go version (1.26)`), consider downgrading `go.mod` to match the version the linter was built with, or ensuring dependencies also support the lower version.
