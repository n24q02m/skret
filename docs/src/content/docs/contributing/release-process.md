---
title: Release Process
description: "skret uses [Python Semantic Release](https://python-semantic-release.readthedocs.io/) (PSR) for automated versioning and [GoReleaser](https://goreleaser.com/) f"
---

skret uses [Python Semantic Release](https://python-semantic-release.readthedocs.io/) (PSR) for automated versioning and [GoReleaser](https://goreleaser.com/) for cross-platform binary builds.

## How It Works

1. **Version bump** -- PSR analyzes commit messages (`feat:` / `fix:`) to determine the next version
2. **Tag creation** -- PSR creates a git tag (`v0.1.0`) and updates `CHANGELOG.md`
3. **Binary build** -- GoReleaser builds binaries for all 6 platforms and publishes to GitHub Releases
4. **Package updates** -- Homebrew tap and Scoop bucket are updated automatically

## Triggering a Release

Releases are triggered via `workflow_dispatch` on the `release.yml` workflow:

```bash
# Stable release
gh workflow run release.yml -f release_type=stable

# Beta/prerelease
gh workflow run release.yml -f release_type=beta
```

Never create tags manually. Always use the workflow.

## Release Types

| Type | Version Example | Use Case |
|------|----------------|----------|
| Stable | `v0.2.0` | Production-ready release |
| Beta | `v0.3.0-beta.1` | Testing before stable |

### Beta to Stable Promotion

1. Release a beta: `gh workflow run release.yml -f release_type=beta`
2. Test the beta build
3. If passing, release stable: `gh workflow run release.yml -f release_type=stable`

PSR automatically determines the version number from commits since the last release.

## Commit Impact on Versions

| Commit Prefix | Version Bump |
|---------------|-------------|
| `fix:` | Patch (0.1.0 -> 0.1.1) |
| `feat:` | Minor (0.1.0 -> 0.2.0) |

During `v0.x`, breaking changes are allowed in minor versions and documented in the CHANGELOG.

## CI/CD Pipeline

```
push to main
  -> ci.yml (lint, test, build)

workflow_dispatch (release.yml)
  -> PSR: analyze commits, bump version, update CHANGELOG, create tag
  -> tag push triggers cd.yml
    -> GoReleaser: build 6 binaries, create GitHub Release
    -> Docker: push ghcr.io/n24q02m/skret:<version>
    -> Homebrew: update tap formula
    -> Scoop: update bucket manifest
    -> Cosign: sign artifacts (keyless, GitHub OIDC)
    -> Syft: generate SBOM
```

## Build Targets

GoReleaser produces binaries for:

| OS | Architecture | Artifact |
|----|-------------|----------|
| Linux | amd64 | `skret_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `skret_VERSION_linux_arm64.tar.gz` |
| macOS | amd64 | `skret_VERSION_darwin_amd64.tar.gz` |
| macOS | arm64 | `skret_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `skret_VERSION_windows_amd64.zip` |
| Windows | arm64 | `skret_VERSION_windows_arm64.zip` |

## CHANGELOG

`CHANGELOG.md` is managed entirely by PSR. Do not edit it manually.

Each release entry includes:

- Version number and date
- Grouped changes under `feat:` and `fix:` headings
- Links to commits and compare URLs

## Verifying a Release

After a release completes:

```bash
# Check the latest release
gh release view --repo n24q02m/skret

# Verify cosign signature
cosign verify-blob \
  --certificate skret_VERSION_linux_amd64.tar.gz.cert \
  --signature skret_VERSION_linux_amd64.tar.gz.sig \
  --certificate-identity-regexp="https://github.com/n24q02m/skret" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  skret_VERSION_linux_amd64.tar.gz
```
