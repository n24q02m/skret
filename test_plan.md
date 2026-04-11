Error: can't load config: the Go language version (go1.24) used to build golangci-lint is lower than the targeted Go version (1.26)

Based on the memory:
Environment Context: The project targets Go 1.26 in go.mod and .golangci.yaml. To resolve version mismatch errors where golangci-lint fails to load configuration for newer target versions, the CI workflow is configured with install-mode: goinstall to build the linter using the project's toolchain.

So I need to modify .github/workflows/ci.yml to use `install-mode: goinstall` in the `golangci-lint-action` step.
