---
title: Nix and aqua channel status
description: "Why Skret does not currently advertise Nix, aqua, or mise as verified installation channels."
---

Nix, aqua, and mise packages are **not currently published or verified Skret installation channels**.

The public `n24q02m/skret-nix` repository and the expected `aquaproj/aqua-registry/pkgs/n24q02m/skret/registry.yaml` entry are absent. The former in-repository `flake.nix` was not a release package: it had no lock file, used a fake vendor hash, hardcoded an unrelated version, and disabled tests. It was removed rather than advertised as an install path.

Use one of the currently supported paths:

- the checksum/signature-verifying one-shot installer;
- Homebrew through `n24q02m/tap`;
- Scoop through `n24q02m/scoop-bucket`;
- `go install github.com/n24q02m/skret/cmd/skret@latest`;
- a release archive verified against `checksums.txt` and `checksums.txt.bundle`.

## Conditions for restoring a channel

Do not add a Nix, aqua, or mise command back to public install documentation until the channel owner provides automated readback that proves:

1. the public package repository or registry entry exists;
2. its version equals the selected stable GitHub Release;
3. every OS/architecture URL resolves to that release;
4. every package checksum equals the release checksum;
5. an install smoke reports the exact selected version;
6. update and rollback behavior is documented;
7. channel publication is bound to the protected stable release transaction.

Checksum consumption alone does not inherit the Sigstore identity verification performed by the one-shot installers. Any restored channel must state exactly which authenticity checks it performs.

The release/channel owner owns this residual. Until those readbacks pass, absence from the install table is intentional rather than a documentation omission.
