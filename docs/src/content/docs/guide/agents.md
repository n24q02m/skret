---
title: Using skret from a script or agent
description: "Exit codes, non-interactive flags, and copy-paste recipes for running skret from CI, cron, or an AI agent."
---

Exit codes, non-interactive flags, and copy-paste recipes for running skret from CI, cron, or an AI agent.

Every skret command is non-interactive by default — the exceptions are `skret rollback` without `--confirm`/`--force` (prompts y/N) and `--from-stdin` at a real terminal (blocks until you send EOF, see below). Output streams are deliberate: **stdout carries data** (secret values, JSON, rendered templates), **stderr carries status** ("Set KEY", warnings, progress). Every failure exits with a distinct, documented code you can branch on instead of parsing stderr text.

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
| 10 | `ExitLeakFound` | `skret scan` found a managed secret value in a tracked (or `--staged`) file |
| 125 | `ExitExecError` | `skret run --` could not exec the command (not found on `$PATH`, or exec failure) |

Two of these are the ones you'll branch on most in automation:

- **`skret scan`** exits **10** when a managed secret value shows up in a file — wire it into a pre-commit hook or a CI leak-guard step. It exits **0** when nothing is found.
- **`skret diff A B --exit-code`** exits **9** when the two secret sets differ, the same non-zero-on-difference contract as `git diff --exit-code`. Without `--exit-code`, `diff` always exits 0 — it's a report, not a gate, unless you ask it to be one.

See the [Error Codes reference](/reference/error-codes/) for the full table plus provider-specific error mappings and remediation per code.

## Non-interactive checklist

- **Exact bytes out**: `skret get KEY --plain`. The default `get` (no `--plain`) appends one trailing newline for terminal readability; `--plain` gives you the value's exact stored bytes with nothing added — use it whenever a script or agent needs the byte-exact value (`skret get TOKEN --plain > token.bin`).
- **Parseable dump**: `skret env --format=json` (also `yaml`, `export`, or the `dotenv` default) — all four formats round-trip byte-exact; pick `json` when a script needs to parse the whole environment.
- **Multi-line value in**: `skret set KEY --from-stdin < file.pem` or `skret set KEY --from-file path`. Both read the *entire* stream/file (not just the first line), so a PEM key or multi-line JSON blob survives with every embedded newline intact.
- **A value that starts with `-`**: pass `--` before the key, or it's parsed as a flag: `skret set -- KEY '-----BEGIN PRIVATE KEY-----...'`.
- **Secrets are byte-exact everywhere except `run`**: `get`, `env`, `template`, and `sync`/`import` preserve every byte, including NUL, CR, and embedded newlines. `skret run`/`skret run --watch` sanitize control bytes on the way into the child process's environment, because an OS process environment can't carry a NUL or embedded newline. Full detail: [Value fidelity](/guide/value-fidelity/).

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

`github` needs `GITHUB_TOKEN` in the environment. `cloudflare` has no flags-only path — it must be declared under `sync.targets` in `.skret.yaml` (worker or pages) and needs `CLOUDFLARE_API_TOKEN`. See [Sync](/guide/sync/).

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
