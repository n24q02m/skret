---
title: Verifying a release
description: "Check a skret release before you run it: the keyless Cosign signature on checksums.txt, SLSA build provenance with gh attestation, and the SPDX SBOM for each archive."
---

Every skret release is built and published by one GitHub Actions workflow, [`.github/workflows/cd.yml`](https://github.com/n24q02m/skret/blob/main/.github/workflows/cd.yml), on GitHub-hosted runners. That workflow leaves three things you can check independently:

| What                         | Proves                                                                         | Tool                |
| ---------------------------- | ------------------------------------------------------------------------------ | ------------------- |
| `checksums.txt.bundle`       | `checksums.txt` was signed by `cd.yml` in `n24q02m/skret` (keyless, Sigstore)  | `cosign`            |
| Build provenance attestation | an archive, installer or bundle was built by `cd.yml` from a specific commit   | `gh attestation`    |
| `<archive>.sbom.json`        | which Go modules, at which versions, are compiled into that archive (SPDX 2.3) | any SPDX tool, `jq` |

The [one-shot installers](/guide/installation/) already run the first check for you. Use this page when you download an archive by hand, mirror releases, or need evidence for an audit.

The examples use the Linux amd64 archive. Replace `VERSION` with the release version without the `v` (for example `1.43.0`) and `vVERSION` with the tag.

## 1. Download

```bash
gh release download vVERSION --repo n24q02m/skret \
  -p 'skret_VERSION_linux_amd64.tar.gz' \
  -p 'skret_VERSION_linux_amd64.tar.gz.sbom.json' \
  -p 'checksums.txt' -p 'checksums.txt.bundle'
```

Archive names follow `skret_VERSION_<os>_<arch>.tar.gz` (`.zip` on Windows); see [installation](/guide/installation/#binary-download) for the full list. `skret-secret-helper` and `skret-compose-supervisor` ship as `skret-secret-helper_VERSION_linux_<arch>.tar.gz` and `skret-compose-supervisor_VERSION_linux_<arch>.tar.gz`, and are verified the same way.

## 2. Verify the Cosign signature

The release workflow signs `checksums.txt` once with keyless Cosign (`cosign sign-blob --bundle`), using the workflow's GitHub OIDC identity. There are no per-archive `.sig` or `.pem` files: the one signature artifact is `checksums.txt.bundle`, a Sigstore bundle holding the signature, the short-lived certificate and the transparency-log entry.

Releases are cut by dispatching `cd.yml` on `main`, so the certificate identity is exactly:

| Field                      | Value                                                                       |
| -------------------------- | --------------------------------------------------------------------------- |
| Identity (certificate SAN) | `https://github.com/n24q02m/skret/.github/workflows/cd.yml@refs/heads/main` |
| OIDC issuer                | `https://token.actions.githubusercontent.com`                               |

```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/n24q02m/skret/.github/workflows/cd.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

`Verified OK` means `checksums.txt` is exactly what that workflow signed. Pin the exact identity as above rather than a loose `--certificate-identity-regexp`: a regexp such as `https://github.com/n24q02m/skret` would also accept any other workflow in the repository.

Then check your files against the now-trusted `checksums.txt`. It lists every archive and every archive SBOM; `--ignore-missing` skips the entries you did not download:

```bash
sha256sum --check --ignore-missing checksums.txt
```

```text
skret_VERSION_linux_amd64.tar.gz: OK
skret_VERSION_linux_amd64.tar.gz.sbom.json: OK
```

Where `sha256sum` is not available (macOS), check the one row you need with `shasum`:

```bash
grep ' skret_VERSION_darwin_arm64.tar.gz$' checksums.txt | shasum -a 256 -c
```

## 3. Verify the build provenance

The release workflow also records [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) (`https://slsa.dev/provenance/v1`) with `actions/attest-build-provenance`. Verify it with the GitHub CLI:

```bash
gh attestation verify skret_VERSION_linux_amd64.tar.gz \
  --repo n24q02m/skret \
  --signer-workflow n24q02m/skret/.github/workflows/cd.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

A zero exit status means the file's SHA-256 digest appears in an attestation signed for `cd.yml` in `n24q02m/skret`, built from `main` on a GitHub-hosted runner. A file that was changed after the build fails with a non-zero exit. Add `--format json` to see the full statement, including the source commit and the workflow run.

These release files are attested:

- every archive: `skret_*`, `skret-secret-helper_*` and `skret-compose-supervisor_*` (`.tar.gz` and `.zip`)
- the installers: `install.sh` and `install.ps1`
- the OCI image archives: `skret-cli.oci.tar` and `skret-sync.oci.tar`
- the bundles: `hub.bundle.tar`, `security-executor.bundle.tar` and `docs.bundle.tar`

SBOM files are not attested themselves; they are covered by the signed `checksums.txt` instead (step 2).

The installer scripts are the other way round: they are attested but not listed in `checksums.txt`. Each one has a plain checksum file next to it, `install.sh.sha256` and `install.ps1.sha256`, that `sha256sum --check` reads. Those files are not signed, so they only catch a corrupted download; to prove where a script came from, run `gh attestation verify install.sh` with the flags above.

## 4. Read the SBOM

Each archive has an SBOM next to it, named `<archive>.sbom.json`. It is an [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON document generated by [syft](https://github.com/anchore/syft) from the archive itself, so it lists the Go modules compiled into the binary inside, with their versions:

```bash
jq -r '.spdxVersion, .creationInfo.creators[]' skret_VERSION_linux_amd64.tar.gz.sbom.json
jq -r '.packages[] | "\(.name) \(.versionInfo)"' skret_VERSION_linux_amd64.tar.gz.sbom.json
```

```text
SPDX-2.3
Organization: Anchore, Inc
Tool: syft-1.51.0
```

Because the SBOM is listed in the signed `checksums.txt`, step 2 already proved it came from the release workflow. Feed it to any SPDX-aware scanner, for example `grype sbom:skret_VERSION_linux_amd64.tar.gz.sbom.json`.

### Auxiliary SBOMs

The release also carries SPDX JSON SBOMs for the artifacts that are not archives:

| SBOM                          | Describes                      |
| ----------------------------- | ------------------------------ |
| `cli-oci.sbom.json`           | `skret-cli.oci.tar`            |
| `sync-oci.sbom.json`          | `skret-sync.oci.tar`           |
| `hub.sbom.json`               | `hub.bundle.tar`               |
| `security-executor.sbom.json` | `security-executor.bundle.tar` |
| `docs.sbom.json`              | `docs.bundle.tar`              |

These are listed in `auxiliary-checksums.txt`, not in `checksums.txt`, with paths prefixed `dist/`:

```bash
gh release download vVERSION --repo n24q02m/skret -p 'cli-oci.sbom.json' -p 'auxiliary-checksums.txt'
sed 's#  dist/#  #' auxiliary-checksums.txt | sha256sum --check --ignore-missing
```

`auxiliary-checksums.txt` is neither signed nor attested, so this check catches a corrupted download but does not prove where the file came from. When you need that proof for an image or bundle, verify the artifact itself with `gh attestation verify` (step 3) and generate its SBOM yourself, for example `syft oci-archive:skret-cli.oci.tar -o spdx-json`.

## Troubleshooting

- **`cosign verify-blob` fails with `no matching CertificateIdentity found`.** The identity or issuer flag does not match the certificate; the error shows the SAN it expected and the one it got. Copy both values from the table in step 2 exactly; the identity ends in `@refs/heads/main`.
- **`gh attestation verify` fails with `HTTP 404: Not Found`.** No attestation exists for that file's digest. Check that you passed a file the workflow attests (step 3 lists them); SBOMs and checksum files are not attested. A file whose content changed after the build also has no attestation.
- **`sha256sum: WARNING: 1 computed checksum did NOT match`.** The file is not the one that was released. Download it again from the release page and do not run it.
