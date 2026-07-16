---
title: Command Reference
description: "Flags, defaults, and behavior for skret's core commands: init, setup, get, set, list, delete, env, run, and import."
---

Flags, defaults, and behavior for skret's core commands. For the guided walkthrough see [Getting Started](/guide/getting-started/); for `.skret.yaml` fields see the [Config Schema Reference](/reference/config-schema/); for exit codes see [Error Codes](/reference/error-codes/).

`skret bootstrap`, `skret sync`, `skret scan`, `skret diff`, and `skret template` each have their own dedicated guide page linked from those commands' `--help` output. `skret history` and `skret rollback` are gated behind `SKRET_EXPERIMENTAL` and are not covered here.

## Global flags

These flags are defined on the root `skret` command and apply to every subcommand below, except where a subcommand defines a local flag of the same name (noted per-command):

| Flag | Description |
|------|-------------|
| `-e, --env <name>` | Target environment (overrides `default_env` in `.skret.yaml`) |
| `--provider <aws\|local>` | Override the provider |
| `--path <prefix>` | Override the secret path prefix |
| `--region <region>` | Override the cloud region |
| `--profile <name>` | Override the cloud profile |
| `--file <path>` | Override the local provider file path |
| `--config <path>` | Load this `.skret.yaml` directly, bypassing directory discovery (see [Configuration](/guide/configuration/#--config-bypass-discovery)) |
| `--log-level <debug\|info\|warn\|error>` | Log level; also settable via `SKRET_LOG` (default `info`) |

`skret init` and `skret setup` each define their own local `--provider`, `--path`, `--region`, and `--file` flags for the config file they write. A local flag shadows the global flag of the same name, so on those two commands `--provider`/`--path`/`--region`/`--file` configure the file being created, not an override for a config load — and `skret init` ignores `--config` entirely, since it always writes to the current directory rather than loading a config. `skret import` likewise defines its own local `--file` (the dotenv source to import from), which shadows the global `--file`.

Most commands below resolve a key positional argument (`<KEY>`) against the environment's path prefix. If Git Bash/MSYS rewrites a bare key or `--path` value into an absolute Windows path, skret recovers the intended value and prints a `warning: ... looked shell-mangled` hint on stderr — set `MSYS_NO_PATHCONV=1` or run from PowerShell to avoid it.

## `skret init`

Creates `.skret.yaml` in the current directory and appends `.secrets.*.yaml` / `.secrets.*.yml` to `.gitignore`.

```bash
skret init --provider=aws --path=/myapp/prod --region=ap-southeast-1
skret init --provider=local --file=./.secrets.dev.yaml
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <aws\|local>` | -- | Provider for the `prod` environment entry |
| `--path <prefix>` | -- | SSM path prefix for the `prod` entry (aws) |
| `--region <region>` | -- | Region for the `prod` entry (aws) |
| `--file <path>` | -- | File path for the `prod` entry (local) |
| `--force` | `false` | Overwrite an existing `.skret.yaml` |

Notes:

- The generated file always has two environments: `dev` (`provider: local`, `file: .secrets.dev.yaml`) and `prod` (`provider: aws`, `path: /myapp/prod`, `region: us-east-1`) with `default_env: dev`. Only the flags you actually pass override the `prod` entry's fields — a bare `skret init` keeps the `/myapp/prod` / `us-east-1` placeholders untouched rather than blanking them.
- Passing `--provider=local` without `--file` sets the `prod` entry's file to `.secrets.prod.yaml`.
- Without `--force`, `init` fails if `.skret.yaml` already exists in the current directory.
- `.gitignore` entries are only appended if not already present, under a `# skret local provider files` header.
- `init` always writes to the current working directory; it does not use config discovery or `--config`.

## `skret setup`

Runs `init` (idempotently, as if `--force` were passed) and then authenticates the provider in one step — the `doppler setup && doppler run` equivalent.

```bash
skret setup
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <aws\|local>` | `aws` | Provider for the `prod` environment entry |
| `--path <prefix>` | -- | SSM path prefix for the `prod` entry (aws) |
| `--region <region>` | -- | Region for the `prod` entry (aws) |
| `--file <path>` | -- | File path for the `prod` entry (local) |
| `--method <sso\|access-key\|profile>` | -- | Auth method passed to `skret auth login` |
| `--opt <key=value>` | -- | Auth option, repeatable (e.g. `--opt start_url=...`) |
| `--yes` | `false` | Confirm running an interactive auth step non-interactively |

Notes:

- With `--provider=local`, `setup` only creates the config — there is nothing to authenticate.
- For any other provider, authentication is interactive (browser SSO device flow, or pasted access keys). Without a terminal attached, `setup` fails fast with an actionable message unless `--yes` is passed to force the attempt, or you use a non-interactive method instead: `skret auth login <provider> --method=profile` (or `--method=assume-role`).
- See the [Authentication guide](/guide/authentication/) for what each `--method` expects and the [Bootstrap guide](/guide/bootstrap/) for provisioning a fresh scoped identity first.

## `skret get <KEY>`

Prints a single secret value to stdout.

```bash
skret get DATABASE_URL
skret get DATABASE_URL --plain
skret get DATABASE_URL --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as a JSON object (`{"key": ..., "value": ...}`, plus `version`/`meta` with `--with-metadata`) |
| `--with-metadata` | `false` | Include version and metadata in the output |
| `--plain` | `false` | Print the exact value bytes with no trailing newline |

Notes:

- Without `--plain`, a trailing newline is appended for terminal readability; use `--plain` when the exact byte count matters (`skret get TOKEN --plain > token.bin`) — see [Value fidelity](/guide/value-fidelity/).
- A missing key exits with `ExitNotFoundError` (5) and a hint to create it with `skret set`; see [Error Codes](/reference/error-codes/).
- To read every secret at once, use `skret env`; to inject secrets into a command, use `skret run`.

## `skret set <KEY> [VALUE]`

Creates or updates a secret's value.

```bash
skret set API_KEY ghp_xxx
skret set -- PRIVATE_KEY "-----BEGIN KEY-----..."
cat key.pem | skret set TLS_KEY --from-stdin
skret set TLS_KEY --from-file key.pem
```

| Flag | Default | Description |
|------|---------|-------------|
| `-s, --from-stdin` | `false` | Read the value from stdin (entire stream, not just the first line) |
| `-f, --from-file <path>` | -- | Read the value from a file |
| `-d, --description <text>` | -- | Secret description, stored as metadata |
| `-t, --tag <key=value>` | -- | Secret tag, repeatable |

Notes:

- The value source is resolved in this order: the positional `VALUE` argument, then `--from-stdin`, then `--from-file`; if none is given, `set` fails with `ExitValidationError` (8).
- `--from-stdin` and `--from-file` both strip trailing `\n` bytes only (embedded newlines are preserved) — see [Value fidelity](/guide/value-fidelity/#reading-a-value-from-stdin-or-a-file).
- A value starting with `-` (a PEM block, a flag-like token) needs `--` before the key so it isn't parsed as a flag: `skret set -- KEY "-----BEGIN..."`.
- Each `--tag` must be `key=value`; a tag without `=` is silently dropped.

## `skret list`

Lists secret key names under the current environment path.

```bash
skret list
skret list --values
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format <table\|json>` | `table` | Output format |
| `--values` | `false` | Decrypt and include values (and version) in the output |
| `--recursive` | `true` | Include keys at any depth under the path, not just the immediate level |

Notes:

- Without `--values`, only key names are listed (table: a `KEY` column; json: `[{"key": ...}, ...]`) — no decryption, no KMS cost.
- With `--values`, the table gains `VERSION` and `VALUE` columns, but the json form only adds `"value"` — it never includes `"version"`.
- `--recursive=false` filters to keys exactly one path segment below the resolved path (e.g. under `/myapp/prod`, `/myapp/prod/DB_URL` matches but `/myapp/prod/nested/KEY` does not).
- An empty result prints `No secrets found. Use 'skret set' to add a secret.` to stderr and exits 0; with `--format=json` it still prints `[]` on stdout.

## `skret delete <KEY>`

Deletes a secret by its key.

```bash
skret delete OLD_TOKEN
```

| Flag | Default | Description |
|------|---------|-------------|
| `--confirm` | `false` | Skip the confirmation prompt |
| `-f, --force` | `false` | Alias for `--confirm` |

Notes:

- Without `--confirm`/`--force`, `delete` prompts `Delete secret "KEY"? [y/N]` on stderr and reads the answer from stdin; anything other than a leading `y`/`Y` cancels with exit 0.
- Deletion is permanent. A missing key exits with `ExitNotFoundError` (5) and a hint to check `skret history <KEY>` (an `SKRET_EXPERIMENTAL`-gated command) for whether it existed before.

## `skret env`

Dumps every secret under the current environment in one of four formats.

```bash
skret env --format=dotenv > .env
skret env --format=json | jq .
eval "$(skret env --format=export)"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format <dotenv\|json\|yaml\|export>` | `dotenv` | Output format |

Notes:

- All four formats round-trip byte-exact — see [Value fidelity](/guide/value-fidelity/). `export` wraps each value in POSIX single quotes for `eval "$(skret env --format=export)"`.
- Keys are converted to environment-variable names and sorted; entries listed under `exclude` in `.skret.yaml` are dropped — see the [Config Schema Reference](/reference/config-schema/#top-level-fields).
- If two secret keys would collide on the same environment-variable name, `env` fails with `ExitConfigError` (2) instead of silently picking one.
- To read a single value use `skret get`; to inject secrets into a running command use `skret run`.

## `skret run -- <command> [args...]`

Runs a command with every secret injected as an environment variable.

```bash
skret run -- make deploy
skret run -- ./server
skret run --watch -- make up-prod
```

| Flag | Default | Description |
|------|---------|-------------|
| `--watch` | `false` | Restart the command whenever a secret changes |
| `--watch-interval <duration>` | `15s` | How often `--watch` checks for changes |

Notes:

- Everything after `--` is passed through to the child command untouched (flag parsing is not interspersed) — a command is required, or `run` fails with `ExitValidationError` (8).
- Values are injected verbatim except for three OS-level constraints: NUL and CR bytes are dropped and LF is replaced with a space — see [Value fidelity](/guide/value-fidelity/#exception-skret-run-sanitizes-control-bytes).
- If `.skret.yaml` declares `required` keys and any are missing from both the resolved secrets and the process environment, `run` fails with `ExitValidationError` (8) before launching the command.
- `--watch` is covered in depth in the [Watch mode guide](/guide/watch/), including the zero-decrypt fingerprint check and restart signal handling.

## `skret import`

Imports secrets from an external source into the current environment.

```bash
skret import --from=dotenv --file=.env
skret import --from=doppler --doppler-project=app --doppler-config=prd
skret import --from=infisical
```

| Flag | Default | Description |
|------|---------|-------------|
| `--from <dotenv\|doppler\|infisical>` | `dotenv` | Import source |
| `--file <path>` | `.env` | Source file path (dotenv only) |
| `--doppler-project <name>` | -- | Doppler project name |
| `--doppler-config <name>` | -- | Doppler config name |
| `--infisical-project-id <id>` | -- | Infisical project ID |
| `--infisical-env <name>` | -- | Infisical environment |
| `--infisical-url <url>` | -- | Infisical API base URL (self-hosted) |
| `--dry-run` | `false` | Preview the keys that would be imported without writing anything |
| `--on-conflict <overwrite\|skip\|fail>` | `skip` | How to handle a key that already exists at the destination |
| `--to-path <prefix>` | -- | Prefix imported keys with this path |

Notes:

- `doppler` and `infisical` sources read their token from `DOPPLER_TOKEN` / `INFISICAL_TOKEN` in the environment, falling back to a credential stored by `skret auth login doppler` / `skret auth login infisical`. Neither is required for `--from=dotenv`.
- Duplicate keys within the imported source are deduplicated before writing (last value wins); keys with an empty value are skipped and reported on stderr.
- `--on-conflict=fail` exits with `ExitConflictError` (6) on the first key that already exists at the destination; `skip` counts and continues; `overwrite` writes without checking.
- This is a one-time migration into skret's backend. For ongoing propagation outward, use [`skret sync`](/guide/sync/) instead.
