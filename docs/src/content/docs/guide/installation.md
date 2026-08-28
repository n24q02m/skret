---
title: Installation
description: "Install Skret through a verified release path on macOS, Linux, or Windows."
sidebar:
  order: 2
---

## Verified One-shot Installer

The installers verify the exact checksum row and Sigstore bundle with `cosign`, validate the bounded `SAFE-ARCHIVE-V1` tree, atomically replace the binary, and roll back if the installed binary cannot report its version.

```bash
# macOS or Linux; cosign must already be on PATH
curl -fsSL https://skret.n24q02m.com/install.sh | sh
```

```powershell
# Windows; cosign must already be on PATH
iwr -useb https://skret.n24q02m.com/install.ps1 | iex
```

`SKRET_INSECURE_SKIP_VERIFY=1` is an explicit signature-verification bypass. It does not bypass checksums, archive/path validation, atomic replacement, or the version smoke.

## Package Managers

### macOS and Linux — Homebrew

```bash
brew install n24q02m/tap/skret
```

### Windows — Scoop

```powershell
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret
```

After a package-manager install, compare `skret --version` with the current stable [GitHub Release](https://github.com/n24q02m/skret/releases/latest). A stale channel is not equivalent to the selected release.

## Go Install

Requires Go 1.26 or newer:

```bash
go install github.com/n24q02m/skret/cmd/skret@latest
```

## OCI Image Status

Skret does not currently advertise a mutable GHCR tag as an installation channel. In particular, do not depend on `ghcr.io/n24q02m/skret:latest`. OCI consumption resumes only after the protected publisher emits an immutable digest plus matching source, checksum, SBOM, signature, and provenance metadata.

## Binary Download

Download pre-built binaries from [GitHub Releases](https://github.com/n24q02m/skret/releases):

| Platform | Architecture | File |
|----------|--------------|------|
| Linux | amd64 | `skret_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `skret_VERSION_linux_arm64.tar.gz` |
| macOS | amd64 | `skret_VERSION_darwin_amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `skret_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `skret_VERSION_windows_amd64.zip` |
| Windows | arm64 | `skret_VERSION_windows_arm64.zip` |

Verify `checksums.txt.bundle` with `cosign`, then verify the downloaded archive against `checksums.txt` before extraction. See the [release verification procedure](/contributing/release-process/#verify-a-published-release).

## Verify Installation

```bash
skret --version
```

The reported version, commit, and build timestamp must match the selected release evidence. Do not use a hardcoded example as artifact identity proof.
