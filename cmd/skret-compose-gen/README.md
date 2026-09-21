# skret-compose-gen

Offline generator for the three signed secret-launch artifacts consumed by
`skret-compose-supervisor`:

| Output          | Type              | Supervisor flag |
| --------------- | ----------------- | --------------- |
| `manifest.json` | `SignedManifest`  | `--manifest`    |
| `trust.json`    | `TrustDocument`   | `--trust`       |
| `model.json`    | `RenderedModel`   | `--compose`     |

All three are written as byte-exact canonical JSON so the supervisor's
`DisallowUnknownFields` + re-encode equality checks pass. The tool never
contacts Docker, a provider, or a VM — it is an offline signer.

## Usage

```sh
# 1. Resolve the compose file first so interpolation is expanded.
docker compose -f docker-compose.yml config > resolved-compose.yml

# 2. Generate an Ed25519 signing key (kept offline; only the public half
#    lands in trust.json).
openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | xxd -p -c 64 > launch.key

# 3. Generate artifacts.
skret-compose-gen \
  --compose resolved-compose.yml \
  --services api,worker \
  --runtime oci-vm-prod \
  --role prod \
  --key launch-key \
  --helper-digest sha256:<sha256 of skret-secret-helper binary> \
  --supervisor-digest sha256:<sha256 of skret-compose-supervisor binary> \
  --wrapper-digest sha256:<sha256 of the wrapper image> \
  --out ./artifacts
```

Install the results as
`/etc/skret/secret-launch/<runtime>.{manifest,trust,model}.json` (mode 0600),
matching the `SECRET_LAUNCH_*` paths in the deploy Makefile.

## Service conversion rules

- `image` must be digest-pinned (`image@sha256:<hex>`); override per service
  with `--image service=image@sha256:<hex>`.
- `argv` is the helper invocation
  (`skret-secret-helper --manifest … --trust … --runtime … --service <name>`);
  `child.argv` is the original `entrypoint` + `command` (scalar form is
  shell-wrapped as `/bin/sh -c`), overridable with
  `--child-argv service='["/app/server","--flag"]'`.
- `restart` is forced to `no` and `open_stdin` to `true`; the supervisor owns
  the lifecycle.
- Secret-named environment entries (`*SECRET*`, `*PASSWORD*`, `*TOKEN*`,
  `*CREDENTIAL*`, `*PRIVATE_KEY*`, `*API_KEY*`) are moved to `keys[]` with
  `--secret-version` (default `1`) and removed from `environment`. Map
  additional secrets explicitly:
  `--secret service=ENV=NAME[:VERSION]` where `NAME` is the provider key.
- `com.skret.secret-launch.*` labels are stripped (the supervisor sets them);
  other secret-like labels are rejected.
- `depends_on` is filtered to the selected services; `networks` are sorted.
- Health checks come from `healthcheck` (CMD / CMD-SHELL / NONE) with
  `--health-*` defaults; heartbeat fields come from `--heartbeat-*`.

## Trust document

`--key` is repeatable (`keyID=source` or bare source; source is a file path,
hex, or base64 — 64-byte private key or 32-byte seed). `--sign-key` selects
which key signs the manifest (default: first `--key`). `--pubkey keyID=base64`
adds trust-only public keys. `--role` and `--runtime-id` are repeatable
allowlists; `key_versions` is auto-populated from every service key plus
`--key-version NAME=VERSION` extras.

## Verification

The generator self-checks after writing: it reloads all three artifacts
through the exact supervisor path (`LoadTrustDocument` →
`VerifySignedManifest` → `ParseRenderedModel` → `ValidateManifestModel`) and
fails if any artifact is rejected. There is no supervisor `--dry-run` mode;
the equivalent offline check is:

```sh
go test ./cmd/skret-compose-gen/ ./internal/secretlaunch/
```

which exercises the same round-trip sign → verify → bind path.

## Docker binary digest

The supervisor refuses to invoke a Docker CLI whose digest does not match
`--docker-sha256`. On the target host:

```sh
sha256sum /usr/bin/docker          # → SECRET_LAUNCH_DOCKER_SHA256=sha256:<hex>
```

The same applies to the supervisor and helper binaries themselves:
`manifest.digests.supervisor` / `manifest.digests.helper` must equal the
sha256 of the installed binaries, so compute them after the version-pinned
install (`sha256sum /usr/local/bin/skret-compose-supervisor` etc.) and pass
them via `--supervisor-digest` / `--helper-digest`.
