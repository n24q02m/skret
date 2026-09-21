---
title: Using skret from a script or agent
description: "Exit codes, non-interactive flags, and copy-paste recipes for running skret from CI, cron, or an AI agent."
---

Exit codes, non-interactive flags, and copy-paste recipes for running skret from CI, cron, or an AI agent.

Every skret command is non-interactive by default — the exceptions are `skret delete` and `skret rollback` without `--confirm`/`--force` (both prompt y/N) and `--from-stdin` at a real terminal (blocks until you send EOF, see below). Output streams are deliberate: **stdout carries data** (secret values, JSON, rendered templates), **stderr carries status** ("Set KEY", warnings, progress). Every failure exits with a distinct, documented code you can branch on instead of parsing stderr text.

## Exit codes

skret returns a distinct exit code per failure class, defined in [`pkg/skret/errors.go`](https://github.com/n24q02m/skret/blob/main/pkg/skret/errors.go):

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `ExitSuccess` | Operation completed successfully |
| 1 | `ExitGenericError` | Unclassified error |
| 2 | `ExitConfigError` | `.skret.yaml` missing or invalid |
| 3 | `ExitProviderError` | Backend provider call failed (e.g. AWS SSM) |
| 4 | `ExitAuthError` | Authentication failed |
| 5 | `ExitNotFoundError` | Secret does not exist |
| 6 | `ExitConflictError` | Key already exists (`import --on-conflict=fail`) |
| 7 | `ExitNetworkError` | Network/connectivity failure |
| 8 | `ExitValidationError` | Invalid input — bad flag combination, missing required value, experimental command not enabled |
| 9 | `ExitDrift` | `skret diff --exit-code` found a difference between the two sides |
| 10 | `ExitLeakFound` | `skret scan` found a managed secret value in a scanned file (working tree, `--staged`, or `--history`) |
| 125 | `ExitExecError` | `skret run --` could not exec the command (not found on `$PATH`, or exec failure) |

Two of these are the ones you'll branch on most in automation:

- **`skret scan`** exits **10** when a managed secret value shows up in a file — wire it into a pre-commit hook or a CI leak-guard step. Add `--history` to walk committed blobs and catch values that were committed and later removed. It exits **0** when nothing is found.
- **`skret diff A B --exit-code`** exits **9** when the two secret sets differ, the same non-zero-on-difference contract as `git diff --exit-code`. Without `--exit-code`, `diff` always exits 0 — it's a report, not a gate, unless you ask it to be one.

See the [Error Codes reference](/reference/error-codes/) for the full table plus provider-specific error mappings and remediation per code.

## The `skret llms` manifest

Instead of hand-writing a cheat sheet for your agent, paste the output of `skret llms` — a names-only capability manifest listing every command with its flags, the supported providers, the exit-code table, the `SKRET_*` environment variables, and the `.skret.yaml` config keys. It is generated from the live command tree and provider registry, so it cannot drift from the binary you are running, and it never contains secret names or values (it reads nothing from config or key material). `--format json` emits the same manifest as a `{version, commands, providers, exit_codes, env_vars, config_keys}` object for programmatic consumption.

```bash
skret llms            # llms.txt-style text; deterministic, so it can be diffed or snapshotted
skret llms --format json
```

## JSON error envelope

Every command inherits a `--format` flag (`table` by default). When a command fails with `--format json`, stderr carries a parseable object instead of the plain-text message — the exit code and the JSON body's `code` field always agree, so a caller can `json.Unmarshal` stderr instead of pattern-matching prose:

```bash
skret get MISSING_KEY --format json
```

```json
{
  "error": "Secret not found. Use 'skret set MISSING_KEY <value>' to create it.: local: get \"MISSING_KEY\": secret not found",
  "code": 5
}
```

`remediation` appears only when the error carries a copy-pasteable fix hint (for example, an auth failure suggesting the exact `skret auth login` command to run) — omitted entirely otherwise, so don't assume the key is always present. A command that already defines its own local `--format` flag (`list`, `env`, `diff`, `scan`, and the write-path commands below) uses that flag's value for its own error rendering too, so `skret delete MISSING --format json` gets the envelope from *that* command's `--format`, not the root one. `get` is the one exception — it has its own `--json` boolean instead of `--format` — but the root `--format` flag still works for it (`skret get MISSING_KEY --format json` above), since `get` has no local flag of that name to shadow it. The root flag exists so every command without an output-format flag of its own can still opt into the envelope.

## Non-interactive checklist

- **Exact bytes out**: `skret get KEY --plain`. The default `get` (no `--plain`) appends one trailing newline for terminal readability; `--plain` gives you the value's exact stored bytes with nothing added — use it whenever a script or agent needs the byte-exact value (`skret get TOKEN --plain > token.bin`).
- **Parseable dump**: `skret env --format=json` (also `yaml`, `export`, or the `dotenv` default) — all four formats round-trip byte-exact; pick `json` when a script needs to parse the whole environment.
- **Multi-line value in**: `skret set KEY --from-stdin < file.pem` or `skret set KEY --from-file path`. Both read the *entire* stream/file (not just the first line), so a PEM key or multi-line JSON blob survives with every embedded newline intact.
- **A value that starts with `-`**: pass `--` before the key, or it's parsed as a flag: `skret set -- KEY '-----BEGIN PRIVATE KEY-----...'`.
- **Secrets are byte-exact everywhere except `run`**: `get`, `env`, `template`, and `sync`/`import` preserve every byte, including NUL, CR, and embedded newlines. `skret run`/`skret run --watch` sanitize control bytes on the way into the child process's environment, because an OS process environment can't carry a NUL or embedded newline. Full detail: [Value fidelity](/guide/value-fidelity/).
- **Multiple config namespaces from one process**: the global `--config <path>` flag loads a specific `.skret.yaml` directly, bypassing directory discovery entirely — useful for a single cron container serving several projects, each declared in its own config file. If the file does not exist the command fails with a config error; it never silently falls back to discovery. See [Configuration](/guide/configuration/).

## JSON output on the write path

`get`, `list`, `env`, `diff`, and `scan` have had `--json`/`--format json` since the read path was built. `set`, `delete`, `history`, and `sync` now carry the same `--format json` (default `table`), so a script driving a full rotation (`set` → verify → `sync`) never has to parse an English status line to know whether a write landed:

```bash
skret set API_KEY --from-stdin --format json < new-key.txt
```

```json
{
  "key": "API_KEY",
  "path": "/myapp/prod",
  "version": 3,
  "created": false
}
```

`created` is `true` only when the key did not exist before this write; the secret value is never included in the payload, in any command's JSON output. `--format json` replaces the human status line (`Set KEY`, `Deleted KEY`, `Synced N secrets to TARGET`) rather than printing both — the payload goes to stdout, so `skret set ... --format json | jq .created` works without stderr noise mixed in.

| Command | `--format json` payload |
|---------|--------------------------|
| `set` | `{"key", "path", "version", "created"}` |
| `delete` | `{"key", "path", "deleted"}` |
| `history` (`SKRET_EXPERIMENTAL=1`) | `[{"version", "value", "updated_at", "author"}, ...]` — `value` is masked unless `--verbose` is also passed, the same policy the table already applies |
| `sync` | `[{"source", "target", "synced"}, ...]`, one entry per target actually written; see [Sync](/guide/sync/#--format-json) |

Every one of these composes with the [JSON error envelope](#json-error-envelope) above: `skret delete MISSING --format json` fails with `{"error": ..., "code": 5}` on stderr instead of the success payload on stdout.

## Recipes

### Read one value

```bash
DB_URL=$(skret get DATABASE_URL --plain)
```

### Inject secrets into a command

```bash
skret run -- ./server
```

Every secret in the resolved environment is injected as a real process environment variable; skret forwards the child's exit code (or exits **125** if the command itself can't be found/exec'd).

### Dump everything for a script to parse

```bash
skret env --format=json | jq -r '.DATABASE_URL'
```

### Sync to CI/CD targets

```bash
skret sync --to=github,cloudflare
```

`github` needs `GITHUB_TOKEN` in the environment. `cloudflare` has no flags-only path — it must be declared under `sync.targets` in `.skret.yaml` (worker or pages) and needs `CLOUDFLARE_API_TOKEN`. Preview first with no writes: `skret sync --to=github --dry-run` prints the exact secret names it would push and exits without writing anything, saving sync state, or touching a dotenv file. Add `--no-overwrite` to only fill keys absent at the target (existing values are never overwritten) — the safer default for an agent driving `sync` unattended. See [Sync](/guide/sync/).

### Leak-guard in a pre-commit hook

```bash
skret scan --staged || { echo "a managed secret would be committed" >&2; exit 1; }
```

Exits **10** on a match, **0** when clean. `--staged` scans only staged content (`git diff --cached`), which is what a commit hook wants. See [Scan](/guide/scan/).

### Migrate an existing `.env` in

```bash
skret import --from=dotenv --file=.env --on-conflict=skip
```

`--on-conflict` defaults to `skip` (silently skip keys that already exist); pass `--on-conflict=fail` to exit **6** (`ExitConflictError`) instead the first time a key collides, or `--on-conflict=overwrite` to replace it.

## Gotchas

- **Leading-dash values.** `skret set KEY -----BEGIN...` fails — skret's flag parser reads `-----BEGIN...` as a flag, not a value. Use `skret set -- KEY value`, or avoid the problem entirely with `--from-stdin`/`--from-file`.
- **`--from-stdin` at an interactive terminal blocks until EOF.** It reads the whole stream, not one line, so with no pipe or redirect it will hang waiting for input — type the value, then send EOF yourself: **Ctrl-D** on macOS/Linux, **Ctrl-Z** then Enter on Windows. In a script, always pipe or redirect: `... --from-stdin < file` or `echo -n "$VALUE" | skret set KEY --from-stdin`.
- **Trailing newlines are stripped; embedded ones are not.** `--from-stdin` and `--from-file` remove only a trailing run of `\n` bytes (so a value saved by a text editor round-trips without gaining an extra newline). A trailing `\r`, or any newline in the middle of the value, is left untouched. See [Value fidelity](/guide/value-fidelity/) for the exact byte-level rules.
- **`skret history` and `skret rollback` are experimental and gated.** Both require `SKRET_EXPERIMENTAL=1` in the environment; without it they exit **8** (`ExitValidationError`) with an explanatory message instead of running:

  ```bash
  SKRET_EXPERIMENTAL=1 skret history DATABASE_URL
  SKRET_EXPERIMENTAL=1 skret rollback DATABASE_URL 3 --confirm
  ```

## The agent e2e guarantee

Everything on this page is enforced, not just documented. The normative source
of these promises is [the skret spec](/reference/spec/) (versioned); the
agent-contract harness turns them into a release gate. The repo ships it at
[`tests/agent-e2e/`](https://github.com/n24q02m/skret/tree/main/tests/agent-e2e)
— it plays the role of an unattended agent against a freshly built `skret`
binary: it inits a local provider in a scratch git repo, then drives a full
session (`get`/`set`/`list`/`env`/`run`/`generate`/`rotate`/`doctor`/`scan`/`delete`)
while asserting the contract at every step:

- **Exit codes**: every failure class exits its documented code (5 not-found,
  2 config, 8 validation, 10 leak, 125 exec, …), in both plain and `--format json` modes.
- **JSON error envelope**: failures with `--format json` print a parseable
  `{"error", "code"}` object on stderr whose `code` equals the process exit code —
  so you can `json.Unmarshal` stderr instead of pattern-matching prose.
- **Byte-exact stdout**: `get --plain` returns the stored bytes exactly
  (trailing spaces, embedded newlines, NUL bytes, multibyte UTF-8 all survive
  the round trip); `rotate --show` prints the value as one line whose bytes
  match a later read.
- **Stream discipline**: data on stdout, status on stderr — a `set` prints
  `Set KEY` on stderr and nothing on stdout, `scan` prints findings on stdout
  and the summary on stderr.
- **Non-interactive**: with no TTY, nothing hangs. `delete` without
  `--confirm` cancels promptly and mutates nothing; every invocation runs
  under a watchdog that turns a suspected prompt into a hard failure.

The harness is always green in CI (the `Agent e2e` workflow runs it on every
pull request, keyless — local provider only, no LLM or cloud credentials), so
a release cannot silently break a script or agent that relies on this page.

Two more things you can use directly:

- **Self-check.** The harness proves it can catch violations: a deliberately
  broken stand-in binary is run through the same workload for each broken
  promise (wrong exit code, mismatched envelope code, missing envelope,
  value on the wrong stream, inexact bytes, a simulated TTY prompt) and must
  be flagged. Run it locally with:

  ```bash
  go test ./tests/agent-e2e/ -run TestSelfCheck -v
  ```

- **Point it at any build.** The hook point for testing a release artifact or
  a future LLM-driven variant — no rebuild of the harness needed:

  ```bash
  SKRET_AGENT_E2E_BINARY=./skret go test ./tests/agent-e2e/ -run TestAgentE2E_ContractSession -v
  ```

On every platform, `skret run -- <cmd>` forwards the child's exit code
byte-for-byte (42 is 42): on unix skret replaces itself via `syscall.Exec`,
and on Windows the child runs as a subprocess whose `ExitError` is returned
verbatim and honored by the exit-code mapper. Exit **125** is reserved for
the case where the command itself could not be executed (not found, spawn
failure). The harness asserts the forwarded code on each platform, so the
contract cannot drift from what this page says.
