---
title: Release Process
description: "How Skret prepares deterministic release candidates, records their identity, and separates preparation from protected publication."
---

Skret's release path has two distinct boundaries:

1. **Prepare** — calculate a candidate, build deterministic artifacts, and record their immutable identity without publishing anything.
2. **Publish and promote** — use an approved, protected publisher to create public release state from the exact prepared candidate.

The repository currently implements only the credential-free **prepare** boundary in `.github/workflows/cd.yml`. It does not create or push a tag, create a GitHub Release, publish a package or image, deploy a Worker, update a package manager, or sign a release.

## Prepare a Candidate

Run the dispatch-only workflow with the candidate channel:

```bash
# Prepare a beta candidate
gh workflow run cd.yml -f release_type=beta

# Prepare a stable-channel candidate; this does not publish or promote it
gh workflow run cd.yml -f release_type=stable
```

The workflow has only `contents: read`, uses one non-cancelling `skret-release-prepare` concurrency lane, and persists no checkout credential. `better-semantic-release` is pinned to a commit and runs in no-operation mode with commit, tag, push, VCS release, and build side effects disabled.

Selecting `stable` calculates and prepares a stable-channel candidate. It is not stable-promotion approval.

## Prepare Pipeline

The prepare job performs these steps:

1. Calculate the candidate version and tag from `semantic-release.toml`.
2. Bind the candidate to the exact source SHA and that commit's timestamp.
3. Build six CLI archives with `.goreleaser.prepare.yaml` and `--skip=publish`.
4. Build multi-platform CLI and sync OCI archives locally.
5. test and type-check the Hub, then build ordinary-Hub and security-executor dry-run bundles.
6. Build the documentation bundle.
7. Generate archive and auxiliary SBOMs, a tracked-source manifest, artifact checksums, and an artifact manifest.
8. Initialize a value-free, hash-chained release transaction journal.
9. Upload the prepared files as seven-day GitHub Actions artifacts.

The prepare configuration intentionally excludes release, signing, publisher, package-manager, and deployment sections. Prepared artifacts are inputs to a later protected publisher, not public releases.

## Candidate Identity and Journal

Every candidate is identified by:

- the exact source SHA;
- channel, candidate version, and candidate tag;
- an artifact-manifest digest;
- an intent digest over the immutable release inputs;
- a transaction ID and hash-chained journal records.

`scripts/release_transaction.py` records strict canonical JSONL transitions. It rejects a changed identity, conflicting replay, a broken hash chain, a partial tail, an invalid transition, or a dispatch record without the external identifier. Ambiguous publication observations move the transaction to `needs_reconciliation`; they are never silently treated as success.

The intended lifecycle is:

```text
prepared -> approved -> dispatching -> dispatched -> completed
               \             \              \
                +------ needs_reconciliation
```

No record contains secret values. A journal is evidence about one transaction; it is not permission to publish.

## Publication and Stable Promotion

Do not create or push release tags manually. Do not rebuild a candidate inside a publisher.

Publication remains closed until the repository has an exact, pinned publisher contract that can:

- consume the prepared source and artifact identity without rebuilding it;
- enforce a protected approval for the requested channel;
- make one idempotent dispatch attempt;
- record the external release identifier and post-publication observation;
- reconcile an ambiguous response before any retry;
- sign published checksum material and preserve provenance;
- update package-manager and deployment surfaces only through their own explicit gates.

Beta publication is a technical release prerequisite once that publisher exists. Stable promotion additionally requires the explicit stable-release decision. Until those conditions are met, a successful `cd.yml` run means **candidate prepared**, not **release published**.

## Candidate Build Targets

GoReleaser prepares:

| OS | Architecture | Archive |
|----|--------------|---------|
| Linux | amd64 | `skret_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `skret_VERSION_linux_arm64.tar.gz` |
| macOS | amd64 | `skret_VERSION_darwin_amd64.tar.gz` |
| macOS | arm64 | `skret_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `skret_VERSION_windows_amd64.zip` |
| Windows | arm64 | `skret_VERSION_windows_arm64.zip` |

The CLI OCI archive is built from the exact Linux binaries extracted from those prepared archives. The sync image, Hub bundles, security-executor bundle, and docs bundle are separate prepared surfaces with their own SBOM and checksum evidence.

## Version Policy

| Commit prefix | Version bump |
|---------------|--------------|
| `fix:` | Patch (`1.12.0` -> `1.12.1`) |
| `feat:` | Minor (`1.12.0` -> `1.13.0`) |

`semantic-release.toml` sets `major_on_zero = false`; a breaking-change commit is a major bump even for a historical `0.x` version. Skret has been on `v1.x` since early 2026.

`CHANGELOG.md` uses semantic-release update mode and the `<!-- version list -->` insertion marker. Do not edit generated release entries or remove that marker.

## Verify a Published Release

This section applies only after the protected publisher has produced a release. The public signature covers `checksums.txt`; each archive is then verified against that authenticated checksum file.

```bash
gh release view vVERSION --repo n24q02m/skret
gh release download vVERSION --repo n24q02m/skret \
  -p 'skret_VERSION_linux_amd64.tar.gz' \
  -p 'checksums.txt' \
  -p 'checksums.txt.bundle'

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp='https://github.com/n24q02m/skret/.+' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum --check --ignore-missing checksums.txt
```

The one-shot installers enforce the same trust chain by default: exact checksum row, non-empty Sigstore bundle, `cosign verify-blob`, bounded `SAFE-ARCHIVE-V1` extraction, atomic replacement, and post-install `skret --version` rollback verification.
