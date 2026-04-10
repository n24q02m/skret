# Bolt Learnings

## Cobra Command Refactoring
Refactoring long Cobra command constructors by introducing an options struct and a dedicated `run` method is an effective way to improve maintainability and readability. This pattern separates flag definitions from execution logic.

## Environment Context
The project requires `GOTOOLCHAIN=auto` to handle the Go version mismatch between `go.mod` (1.26) and the local environment (1.24.3).
