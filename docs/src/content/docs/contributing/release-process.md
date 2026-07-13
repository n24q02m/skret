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

Releases are triggered via `workflow_dispatch` on the `cd.yml` workflow:

```bash
# Stable release
gh workflow run cd.yml -f release_type=stable

# Beta/prerelease
gh workflow run cd.yml -f release_type=beta
```

Never create tags manually. Always use the workflow.

## Release Types

| Type | Version Example | Use Case |
|------|----------------|----------|
| Stable | `v0.2.0` | Production-ready release |
| Beta | `v0.3.0-beta.1` | Testing before stable |

### Beta to Stable Promotion

1. Release a beta: `gh workflow run cd.yml -f release_type=beta`
2. Test the beta build
3. If passing, release stable: `gh workflow run cd.yml -f release_type=stable`

PSR automatically determines the version number from commits since the last release.

## Commit Impact on Versions

| Commit Prefix | Version Bump |
|---------------|-------------|
| `fix:` | Patch (`1.12.0` -> `1.12.1`) |
| `feat:` | Minor (`1.12.0` -> `1.13.0`) |

`semantic-release.toml` sets `major_on_zero = false`, so unlike the PSR
default, this project never treated 0.x minor bumps as safe for breaking
changes -- a breaking-change commit bumps the **major** version regardless
of whether the project is pre- or post-1.0. The project has been on `v1.x`
since early 2026; there is no active `v0.x` phase to describe.

## CI/CD Pipeline

```
push to main
  -> ci.yml (lint, test, build)

workflow_dispatch (cd.yml: "release" job)
  -> PSR: analyze commits, bump version, update CHANGELOG, create + push tag
  -> cd.yml: "goreleaser" job (same run, needs: release)
    -> GoReleaser: build 6 binaries, create GitHub Release
    -> Docker: push ghcr.io/n24q02m/skret:<version>
    -> Homebrew: update tap formula
    -> Scoop: update bucket manifest
    -> Cosign: sign artifacts (keyless, GitHub OIDC)
    -> Syft: generate SBOM

(a raw `git tag vX.Y.Z && git push --tags` also triggers cd.yml's
"goreleaser" job directly, without the "release" job -- recovery path,
not routine use; see "Never create tags manually" above)
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

`CHANGELOG.md` uses PSR's `update` mode: new release sections are spliced in right below the
`<!-- version list -->` marker near the top of the file on every release. Do not remove that marker
— without it, PSR silently leaves the file unchanged (by design, not an error) instead of appending
new content. Do not switch to `init` mode either — that regenerates the whole file from full git
history on every run.

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
