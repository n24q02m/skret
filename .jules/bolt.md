# Learnings

- Testing unexported functions in Go can be done by creating a test file in the same package (e.g., `errors_internal_test.go` in `package aws`).
- Table-driven tests are effective for testing pure functions with multiple input cases like error mapping.
