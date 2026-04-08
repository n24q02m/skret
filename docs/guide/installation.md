# Installation

## Package Managers

### macOS — Homebrew

```bash
brew install n24q02m/tap/skret
```

### Windows — Scoop

```powershell
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret
```

## Go Install

Requires Go 1.26+:

```bash
go install github.com/n24q02m/skret/cmd/skret@latest
```

## Docker

```bash
docker pull ghcr.io/n24q02m/skret:latest

# Usage
docker run --rm \
  -v $(pwd):/app -w /app \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
  ghcr.io/n24q02m/skret list
```

## Binary Download

Download pre-built binaries from [GitHub Releases](https://github.com/n24q02m/skret/releases):

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | amd64 | `skret_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `skret_VERSION_linux_arm64.tar.gz` |
| macOS | amd64 | `skret_VERSION_darwin_amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `skret_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `skret_VERSION_windows_amd64.zip` |
| Windows | arm64 | `skret_VERSION_windows_arm64.zip` |

## Verify Installation

```bash
skret --version
# Output: skret 0.1.0 (commit: abc123, built: 2026-04-08T00:00:00Z)
```
