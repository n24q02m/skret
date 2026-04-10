# Learnings - Test Coverage for Windows Run

- **Windows Execution via Subprocess**: On Windows, Go's `syscall.Exec` is not available, so process replacement is simulated using `os/exec.Command`. This creates a child process while the parent waits.
- **Unix Execution via Process Replacement**: On Unix, `syscall.Exec` replaces the current process. Testing this requires a helper process pattern where the test binary re-executes itself to avoid killing the test runner.
- **CLI Sync Testing**: Testing GitHub sync requires the `GITHUB_TOKEN` environment variable to be set, otherwise the command fails at validation before any sync logic is executed.
