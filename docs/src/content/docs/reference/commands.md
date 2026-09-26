---
title: Command Reference
description: "Flags, defaults, and behavior for skret's core commands: init, setup, get, set, list, delete, env, run, and import."
---

Flags, defaults, and behavior for skret's core commands. For the guided walkthrough see [Getting Started](/guide/getting-started/); for `.skret.yaml` fields see the [Config Schema Reference](/reference/config-schema/); for exit codes see [Error Codes](/reference/error-codes/).

`skret bootstrap`, `skret sync`, `skret scan`, `skret diff`, `skret template`, and `skret doctor` each have their own dedicated guide page linked from those commands' `--help` output. `skret history` and `skret rollback` are gated behind `SKRET_EXPERIMENTAL` and are not covered here.

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
skret get DATABASE_URL --no-resolve
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as a JSON object (`{"key": ..., "value": ...}`, plus `version`/`meta` with `--with-metadata`) |
| `--with-metadata` | `false` | Include version and metadata in the output |
| `--plain` | `false` | Print the exact value bytes with no trailing newline |
| `--no-resolve` | `false` | Print the raw stored value without resolving `${KEY}` references |

Notes:

- Without `--plain`, a trailing newline is appended for terminal readability; use `--plain` when the exact byte count matters (`skret get TOKEN --plain > token.bin`) — see [Value fidelity](/guide/value-fidelity/).
- A missing key exits with `ExitNotFoundError` (5) and a hint to create it with `skret set`; see [Error Codes](/reference/error-codes/).
- `${KEY}` references to sibling secrets are resolved before printing (same environment scope, up to 10 references deep) — a value `postgres://${DB_USER}:${DB_PASS}@host` prints fully composed. `\${KEY}` and `$${KEY}` stay literal byte-exact; an undefined reference fails with `ExitValidationError` (8). Use `--no-resolve` for the raw stored bytes.
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
| `--ttl <duration>` | -- | Record expiry metadata (e.g. `720h`, `12h30m`, `30d`). Stored as the `skret-expires-at` resource tag on AWS and as file metadata on the local provider; `skret list --values` surfaces it and warns when a key is expired or expires within 7 days. Omitting the flag leaves any recorded expiry untouched |
| `--format <table\|json>` | `table` | `json` prints `{"key", "path", "version", "created"}` to stdout instead of the `Set KEY` stderr line — the secret value is never included |
| `--strict-notify` | `false` | Fail the command (exit 7) if the [mutation webhook](/reference/config-schema/#notify-fields) fails; default is warn on stderr only |

Notes:

- The value source is resolved in this order: the positional `VALUE` argument, then `--from-stdin`, then `--from-file`; if none is given, `set` fails with `ExitValidationError` (8).
- `--from-stdin` and `--from-file` both strip trailing `\n` bytes only (embedded newlines are preserved) — see [Value fidelity](/guide/value-fidelity/#reading-a-value-from-stdin-or-a-file).
- A value starting with `-` (a PEM block, a flag-like token) needs `--` before the key so it isn't parsed as a flag: `skret set -- KEY "-----BEGIN..."`.
- Each `--tag` must be `key=value`; a tag without `=` is silently dropped.
- See [Using skret from a script or agent](/guide/agents/#json-output-on-the-write-path) for the full `--format json` payload shapes across `set`/`delete`/`sync`.
- When a [`notify`](/reference/config-schema/#notify-fields) block is configured, a successful set POSTs a names-only `set` event to the webhook.

## `skret generate`

Generates a random value (password, UUID, hex, or base64) with crypto/rand. Works offline — no provider or `.skret.yaml` is needed unless `--set` is used.

```bash
skret generate --type password --length 32
skret generate --type hex --length 16 --count 5
skret generate --type password --charset alnum+symbols --format json
skret generate --type password --set API_KEY
```

| Flag | Default | Description |
|------|---------|-------------|
| `--type <password\|uuid\|hex\|base64>` | `password` | Value type |
| `--length <n>` | `32` | Output length in characters (1–1048576). Ignored for uuid (fixed 36); passing `--length` with uuid is a validation error |
| `--charset <alnum\|alnum+symbols\|symbols>` | `alnum` | Password alphabet only: alnum is `A-Za-z0-9`; the symbol set is `!@#$%^&*()-_=+[]{};:,.` |
| `--count <n>` | `1` | Number of values (1–10000) |
| `--set <KEY>` | -- | Also store the value as secret `KEY` via the configured provider (requires config; count must be 1) |
| `--plain` | `false` | Print exact value bytes with no trailing newline (count must be 1) |
| `--format <table\|json>` | `table` | `json` prints `{"value", "type", "length"}` (an array of those objects when `--count` > 1); `key` is added when `--set` stored the value |

Notes:

- stdout carries only the generated value(s) — one per line by default, raw bytes with `--plain`; status (the `Set KEY` line) goes to stderr. See [Value fidelity](/guide/value-fidelity/).
- All randomness comes from `crypto/rand`; mapping bytes onto an alphabet uses rejection sampling, so every character of the chosen charset is equally likely (no modulo bias).
- hex uses lowercase `0-9a-f`; base64 uses the standard alphabet `A-Za-z0-9+/` without padding.
- uuid is RFC 4122 version 4 (36 characters, fixed format); `--length` and `--charset` do not apply and are rejected if passed.
- Invalid flags or values exit `ExitValidationError` (8) with a remediation hint; with `--format json` the error is a `{"error", "code", "remediation"}` envelope like every other command.

## `skret rotate <KEY> [KEY...]`

Replaces a secret's value with a fresh generated value and records the change — the write counterpart to [`skret generate`](#skret-generate) for keys that already exist.

```bash
skret rotate API_KEY
skret rotate API_KEY --type hex --length 64
skret rotate API_KEY --value ghp_replacedmanually --ttl 720h
skret rotate API_KEY DB_PASS --yes --format json
skret rotate API_KEY --show
```

| Flag | Default | Description |
|------|---------|-------------|
| `--generate` | `true` | Draw the new value from the generate engine (same `--type`/`--length`/`--charset` rules as `skret generate`) |
| `--value <text>` | -- | Store this explicit value instead of generating; mutually exclusive with an explicit `--generate` |
| `--type <password\|uuid\|hex\|base64>` | `password` | Generated value type |
| `--length <n>` | `32` | Generated length in characters (1–1048576; uuid fixed 36) |
| `--charset <alnum\|alnum+symbols\|symbols>` | `alnum` | Generated password alphabet |
| `--ttl <duration>` | -- | Record expiry metadata (e.g. `720h`, `12h30m`, `30d`). Stored as the `skret-expires-at` resource tag on AWS and as file metadata on the local provider. Omitting the flag continues any existing cadence |
| `--yes` | `false` | Skip the confirmation prompt |
| `--show` | `false` | Print the new value on stdout (one line per key, or the `"value"` field in json) |
| `--strict-notify` | `false` | Fail the command if the mutation webhook fails (default: warn only) |
| `--format <table\|json>` | `table` | `json` prints `{"key", "path", "rotated", "version"}` per key (plus `"expires_at"` when recorded); one object for a single key, an array for several |

Notes:

- Non-interactive by design: the confirmation prompt appears only on an interactive terminal — CI and piped invocations rotate without asking; `--yes` skips it there too.
- The new value is never printed unless `--show`: stdout carries nothing (table) or the JSON envelope (`--format json`); `Rotated KEY` status goes to stderr.
- Every key is checked before any key rotates, so a missing key fails the whole invocation with `ExitNotFoundError` (5) and leaves every value untouched.
- Each rotation is a new provider version, visible via `skret history KEY` where the provider tracks versions (e.g. AWS; the local provider does not keep history).
- On AWS the expiry rides the provider-native `skret-expires-at` resource tag; on the local provider it is a `meta:` field in the secrets file (kept outside the encrypted value region — it stays readable metadata in the envelope header). `skret list --values` surfaces both and warns on stderr when a key is expired or expires within 7 days.

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
- With `--values`, the table gains `VERSION`, `VALUE`, and `EXPIRES` columns (`-` when no expiry is recorded), but the json form only adds `"value"` and `"expires_at"` (when recorded) — it never includes `"version"`. Expiry metadata is written by `set --ttl` / `rotate --ttl`; keys near expiry (within 7 days) or expired produce a stderr warning.
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
| `--format <table\|json>` | `table` | `json` prints `{"key", "path", "deleted"}` to stdout instead of the `Deleted KEY` stderr line |
| `--strict-notify` | `false` | Fail the command (exit 7) if the [mutation webhook](/reference/config-schema/#notify-fields) fails; default is warn on stderr only |

Notes:

- Without `--confirm`/`--force`, `delete` prompts `Delete secret "KEY"? [y/N]` on stderr and reads the answer from stdin; anything other than a leading `y`/`Y` cancels with exit 0.
- Deletion is permanent. A missing key exits with `ExitNotFoundError` (5) and a hint to check `skret history <KEY>` (an `SKRET_EXPERIMENTAL`-gated command) for whether it existed before — with `--format json`, the error is the JSON envelope described in [Using skret from a script or agent](/guide/agents/#json-error-envelope), still carrying `"code": 5`.
- When a [`notify`](/reference/config-schema/#notify-fields) block is configured, a successful delete POSTs a names-only `delete` event to the webhook.

## `skret env`

Dumps every secret under the current environment in one of four formats.

```bash
skret env --format=dotenv > .env
skret env --format=json | jq .
eval "$(skret env --format=export)"
skret env --no-resolve
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format <dotenv\|json\|yaml\|export>` | `dotenv` | Output format |
| `--no-resolve` | `false` | Dump raw stored values without resolving `${KEY}` references |

Notes:

- All four formats round-trip byte-exact — see [Value fidelity](/guide/value-fidelity/). `export` wraps each value in POSIX single quotes for `eval "$(skret env --format=export)"`.
- Keys are converted to environment-variable names and sorted; entries listed under `exclude` in `.skret.yaml` are dropped — see the [Config Schema Reference](/reference/config-schema/#top-level-fields).
- If two secret keys would collide on the same environment-variable name, `env` fails with `ExitConfigError` (2) instead of silently picking one.
- `${KEY}` references are resolved per value against the full environment scope before dumping (excluded keys remain resolvable as targets); an undefined reference or cycle fails with `ExitValidationError` (8). `--no-resolve` dumps the raw stored values.
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
| `--no-resolve` | `false` | Inject raw stored values without resolving `${KEY}` references |

Notes:

- Everything after `--` is passed through to the child command untouched (flag parsing is not interspersed) — a command is required, or `run` fails with `ExitValidationError` (8).
- Values are injected verbatim except for three OS-level constraints: NUL and CR bytes are dropped and LF is replaced with a space — see [Value fidelity](/guide/value-fidelity/#exception-skret-run-sanitizes-control-bytes).
- `${KEY}` references are resolved before injection (same scope as `env`), and re-resolved on every `--watch` restart; `--no-resolve` injects the raw stored values.
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

## `skret keys init`

Sets up key material for local-file encryption and optionally migrates the plaintext file in place.

```bash
skret keys init
skret keys init --encrypt-existing
skret keys init --file=./.secrets.dev.yaml --encrypt-existing --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--file <path>` | active env's `file` | Local provider file to act on |
| `--encrypt-existing` | `false` | Convert the plaintext file to an encrypted envelope (atomic write, 0600) and record `encrypted: true` for the active environment in `.skret.yaml` |
| `--passphrase-stdin` | `false` | Read the passphrase from one stdin line instead of generating/storing a key |
| `--format <table\|json>` | `table` | `json` prints `{key_source, keyring_stored, file, file_encrypted, already_encrypted, config_updated, kdf}` to stdout |

Notes:

- Key sourcing precedence: `SKRET_AGE_KEY` / `SKRET_LOCAL_KEY` already set (validated, nothing stored) → a fresh 256-bit key generated and stored in the OS keyring (service `skret`, user `local-enc-key`, verified round-trip) → `--passphrase-stdin` → interactive passphrase prompt with confirmation (only when stdin is a terminal).
- Key material is never printed, logged, or included in the JSON payload.
- With `--encrypt-existing` on an already-encrypted file, init verifies the current key material decrypts it and reports `already_encrypted` instead of rewriting.
- If the file does not exist yet, `--encrypt-existing` records the config flag; the first write under it creates the envelope.
- In non-interactive contexts (CI, scripts) with no env material and no usable keyring, init fails with `ExitAuthError` (4) and a remediation hint instead of prompting.

## `skret keys show`

Reports the encryption state of the local provider file. Secret values are never printed.

```bash
skret keys show
skret keys show --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format <table\|json>` | `table` | `json` prints a `{encrypted, format, kdf, encrypted_config, key_available, key_source, warnings}` object |

Notes:

- `encrypted` reflects the file on disk (envelope sniffing), `encrypted_config` the `encrypted: true` flag in `.skret.yaml` — the two can legitimately differ while a plaintext file is awaiting migration.
- `key_available` is checked non-interactively (env vars and OS keyring only), so scripts can rely on it without triggering a prompt.

## `skret audit`

Shows the secret access audit trail. Read-only: never mutates state, fully non-interactive, and stdout carries data only.

```bash
skret audit
skret audit --since 24h --key API_KEY
skret audit --format json
skret audit --provider aws --since 2026-09-01T00:00:00Z --limit 50
```

**Local provider** — renders the append-only JSONL audit trail written next to the secrets file (`.skret-audit.log`, or the `audit_log` path from `.skret.yaml`). Every local `set`/`rotate`/`delete` appends one line:

```json
{"timestamp":"2026-09-19T09:00:00.123Z","op":"set","key_names":["API_KEY"],"env":"prod","actor":"deploy-bot"}
```

Each line carries timestamp, operation (`set`/`rotate`/`delete`), affected key names, environment, and actor (`SKRET_ACTOR` when set — useful in CI — else the OS user). Secret values are never written to the trail. The log is created with `0600`, and when it reaches 1 MiB it rotates to `.skret-audit.log.1` (single backup) before the next append. Reading the trail never decrypts the secrets file, so `skret audit` works without key material.

**AWS provider** — exports CloudTrail events for SSM Parameter Store operations (`GetParameter`, `GetParameters`, `GetParametersByPath`, `GetParameterHistory`, `PutParameter`, `DeleteParameter`, `DeleteParameters`), newest first. CloudTrail lookup retention is 90 days, so `--since` older than that yields whatever the service still returns. Credentials resolve exactly like the AWS provider itself (stored credential → profile → SDK chain); region comes from the environment config or `--region`. CloudTrail never logs parameter values, and skret renders metadata fields only.

| Flag | Default | Description |
|------|---------|-------------|
| `--since <duration\|RFC3339>` | -- | Only entries newer than this (`24h`, `30d`, or an absolute timestamp). Local filtering is exact; AWS uses it as the CloudTrail lookup window start. |
| `--key <name>` | -- | Only entries for this exact key/parameter name |
| `--limit <n>` | `0` (all) | Cap rendered events, keeping the most recent. The AWS sweep additionally bounds itself at 10 LookupEvents pages (500 events) per event name. |
| `--format <table\|json>` | `table` | `table` prints a `TIME OP ENV KEYS ACTOR` grid (local) / `TIME EVENT PARAMETER USER SOURCE` grid (AWS); `json` prints the entry array on stdout |

| Exit code | Meaning |
|-----------|---------|
| 0 | Entries rendered (an empty trail is not an error; a note goes to stderr) |
| 2 | Config load/resolve failed |
| 3 | Trail unreadable, or the CloudTrail lookup failed (auth/permission/network) |
| 8 | Invalid flag value (`--format`, `--limit`, `--since`) or a provider without a skret-managed audit trail |

## `skret doctor`

Read-only health check for the current skret setup. Prints one `PASS`/`WARN`/`FAIL` line per check on stderr and a summary on stdout; exits `0` when everything passes (warnings never fail), otherwise with the failing check's error class.

```bash
skret doctor
skret doctor --env prod
skret doctor --format json
```

Checks: config parse/schema (`config`), per-environment provider reachability (`provider[env]` — a real `sts:GetCallerIdentity` probe for AWS, secrets-file load for `local`), stored-credential state (`auth[aws]` — missing warns, expired fails, expiry within 24h warns), local secrets-file permissions (`permissions[env]`, advisory; always pass on Windows), local at-rest encryption state (`encryption[env]` — encrypted file with key available passes, encrypted without key fails with an auth-class error and a `SKRET_AGE_KEY` remediation, plaintext warns with high-entropy key names), and TTL hygiene (`expiry[env]` — past-expiry and 7-day-window counts for secrets carrying expiry metadata; advisory, emitted only when TTL metadata exists).

| Flag | Default | Description |
|------|---------|-------------|
| `--format <table\|json>` | `table` | `json` prints `{checks: [{name, status, detail, remediation?}]}` on stdout |
| `--timeout <duration>` | `10s` | Reachability probe timeout per provider |

| Exit code | Meaning |
|-----------|---------|
| 0 | All checks passed (warnings allowed) |
| 2 | Config check failed |
| 3 | Local provider check failed (e.g. corrupt secrets file) |
| 4 | Auth check failed (expired credential) |
| 7 | Provider unreachable |


## `skret llms`

Prints a names-only capability manifest for LLM agents: every command with its flags, the supported providers, the exit-code table, the `SKRET_*` environment variables, and the `.skret.yaml` config keys. Paste it into an agent session as in-context documentation, or point the agent at `skret llms --format json`.

The manifest is generated from the live command tree and provider registry, so it always matches the binary you are running. Names only: secret names and values are never included, and nothing is read from config or key material, so the command works anywhere skret runs. Output is deterministic — identical invocations are byte-identical, so it can be diffed or snapshotted. Read-only, non-interactive, exits 0.

```bash
skret llms
skret llms --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format <table\|json>` | `table` | `json` prints a `{version, commands[], providers[], exit_codes{}, env_vars[], config_keys[]}` object |

| Exit code | Meaning |
|-----------|---------|
| 0 | Manifest printed |
| 8 | Invalid flag value (`--format`) or an unexpected positional argument |
## `skret-mcp` (companion binary)

An MCP (Model Context Protocol) server that exposes the same `.skret.yaml` project to AI agent harnesses (Claude Code, OMP, any stdio MCP client) — newline-delimited JSON-RPC 2.0 on stdin/stdout, diagnostics on stderr. See the [MCP guide](/guide/mcp/) for client wiring and the write-gate policy.

Tools: `skret_list` (key names only), `skret_get` (the single value-returning tool), `skret_env` (accessible environment names), `skret_status`/`skret_doctor` (health, no network calls), plus write tools `skret_set`/`skret_delete`/`skret_rotate` that are rejected unless `mcp.allow_write: true` is set under the optional `mcp:` config block (which also carries the optional `allowed_envs` filter) and each write call additionally carries `confirm: true`. Local-provider reads through MCP are appended to the audit trail as `mcp_read` entries.

| Flag | Default | Description |
|------|---------|-------------|
| `--workdir <dir>` | current directory | Directory to discover `.skret.yaml` from |
| `--env <name>` | `default_env` | Pin the environment |
| `--provider <name>` | config | Override the provider |
| `--path <prefix>` | config | Override the secret path prefix |
| `--version` | -- | Print version and exit |

| Exit code | Meaning |
|-----------|---------|
| 0 | Clean shutdown (stdin closed or signal) |
| 1 | Transport/read failure mid-session |
| 2 | Configuration could not be discovered or loaded (including a startup `--env` outside `mcp.allowed_envs`) |
