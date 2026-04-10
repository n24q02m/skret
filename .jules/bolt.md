# Bolt Persona Learnings

## Testing syscall.Exec in Go
Testing `syscall.Exec` in Go requires a helper process pattern where the test binary re-executes itself (using `os.Executable()` and `-test.run`) to avoid terminating the main test runner. A guard environment variable is used to ensure the helper logic only runs in the intended subprocess.

## Go Version and Tooling
If `go.mod` specifies a Go version higher than what is available in the environment (e.g., Go 1.26 while the environment or linter only supports up to Go 1.25), it can cause CI failures, especially with `golangci-lint`. Downgrading the version in `go.mod` and `.golangci.yaml` to a compatible version (e.g., 1.24) can resolve these issues if the code doesn't rely on newer features.
