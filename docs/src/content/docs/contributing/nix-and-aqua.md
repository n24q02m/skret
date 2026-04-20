---
title: Nix flake + aqua-registry
description: "How to install skret via Nix and how the aqua-registry entry is kept in sync with each release."
---

skret ships a Nix flake and is registered in the [aqua-registry](https://github.com/aquaproj/aqua-registry). Both channels install directly from the official GitHub release artifacts, so they inherit the cosign signatures and SBOMs attached to the upstream tag.

## Nix — from the flake

```sh
nix run github:n24q02m/skret
# or, in a shell
nix shell github:n24q02m/skret
```

To pin a specific release:

```sh
nix run "github:n24q02m/skret?ref=v1.0.0"
```

First-time builds need a vendor hash — `vendorHash` in `flake.nix` starts as `lib.fakeHash`; the first `nix build` prints the real hash in the error, paste it in and commit.

## Nix — from nixpkgs (pending)

A `pkgs/by-name/sk/skret/package.nix` is queued for nixpkgs; once merged the following will work without a flake:

```sh
nix shell nixpkgs#skret
```

## aqua + mise

[aqua](https://aquaproj.github.io) caches signed release binaries directly. [mise](https://mise.jdx.dev) re-uses the aqua backend when installed, so `mise use -g aqua:n24q02m/skret@latest` gives you the same binary + checksum as `curl | sh`.

`registry.yaml` entry (mirrored to `aquaproj/aqua-registry/pkgs/n24q02m/skret/registry.yaml`):

```yaml
packages:
  - type: github_release
    repo_owner: n24q02m
    repo_name: skret
    asset: "skret_{{ trimV .Version }}_{{ title .OS }}_{{ .Arch }}.{{ .Format }}"
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    replacements:
      amd64: amd64
      arm64: arm64
    supported_envs:
      - darwin
      - linux
      - windows
    checksum:
      type: github_release
      asset: "checksums.txt"
      algorithm: sha256
```

Once aqua-registry PR is merged:

```sh
aqua install n24q02m/skret
mise use -g aqua:n24q02m/skret@latest
```
