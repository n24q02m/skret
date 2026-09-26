# The skret spec

```
spec version: 1
status:       normative
published:    2026-09-26
applies-to:   skret v1.33.x (main)
```

The machine-readable contract for `skret`: exit codes, the JSON envelope, stream
discipline, byte-exact guarantees, non-interactive behavior, and llms.txt
coverage. The key words MUST, MUST NOT, SHOULD, and MAY are interpreted as
described in RFC 2119.

Every claim in this document is enforced by code, not prose:

- `pkg/skret/errors.go` — the exit-code constants and resolution logic.
- `pkg/skret/spec_conformance_test.go` — CI enforces the exit-code table on
  every run.
- `cmd/skret/main.go` — the single process exit path.
- `internal/cli/errjson.go` — the JSON error envelope.
- `tests/agent-e2e` + `.github/workflows/agent-e2e.yml` — an always-on CI
  harness that drives the built binary the way an unattended agent would and
  fails on any deviation from this contract.

The rendered human version lives at
<https://skret.n24q02m.com/reference/spec/>; where the two differ, they must be
reconciled in the same PR — divergence is a bug.

## 1. Exit-code contract

skret exits with exactly one code from this table. Codes are a closed set: a
release MUST NOT exit with any other value, and adding a value requires a spec
minor version.

| Code | Constant (`pkg/skret`) | Meaning |
|-----:|------------------------|---------|
| 0 | `ExitSuccess` | Operation completed successfully. |
| 1 | `ExitGenericError` | Unclassified error; also the fallback when an error carries no typed exit code. |
| 2 | `ExitConfigError` | Configuration problem: missing/invalid `.skret.yaml`, unsupported schema `version`, undeclared environment, env-name collision, `--config` pointing at a missing file. |
| 3 | `ExitProviderError` | Backend provider failure (SSM / Key Vault / Secret Manager / Vault / local I/O). |
| 4 | `ExitAuthError` | Authentication failed: credentials missing/invalid, or no encryption key material for the local encrypted provider. |
| 5 | `ExitNotFoundError` | Secret does not exist (e.g. `get`, `delete` on an absent key). |
| 6 | `ExitConflictError` | Resource conflict: `skret import --on-conflict=fail` hits an existing destination key. |
| 7 | `ExitNetworkError` | Network/connectivity failure reaching the provider. |
| 8 | `ExitValidationError` | Input validation failed: bad flag value, unresolvable `${KEY}` reference (missing name, cycle, depth), non-interactive command missing required confirmation input. |
| 9 | `ExitDrift` | Drift detected — only `diff --exit-code` sets this, when the compared sets differ. |
| 10 | `ExitLeakFound` | A managed secret value was found in a scanned file (`scan`, `scan --staged`, `scan --history`). |
| 125 | `ExitExecError` | The child command passed to `run --` could not be executed (matches the docker/podman exec convention). |

Rules:

- There is exactly ONE exit path: `cmd/skret/main.go` resolves
  `skret.ExitCode(err)` and calls `os.Exit`. Command implementations MUST NOT
  call `os.Exit`.
- `ExitCode(err)` resolution order: the `*skret.Error.Code` if the chain
  carries one; otherwise any error in the chain implementing
  `interface{ ExitCode() int }` (the mechanism leaf packages such as
  `internal/keystore` use to carry codes without an import cycle); otherwise
  `1` (`ExitGenericError`).
- Codes 9 and 10 are successful commands with findings: the scan/diff did its
  job; the code IS the finding. They are not failures.
- A command MAY add a flag that changes its exit code only when the flag names
  it (the `diff --exit-code` pattern).

## 2. JSON envelope

### 2.1 Error envelope

When a command invoked with `--format json` fails, it MUST print exactly one
JSON object to **stderr**:

```json
{
  "error": "delete \"api-key\" failed: boom",
  "code": 3,
  "remediation": "fix: check provider credentials"
}
```

Field set is fixed (`internal/cli/errjson.go`):

- `error` (string, required): the human-readable error text, identical to what
  the table format would print.
- `code` (int, required): the exact exit code the process will exit with (§1).
  A caller may unmarshal the envelope instead of guessing `os.Exit` semantics.
- `remediation` (string, optional): one-line, copy-pasteable fix hint. Omitted
  entirely (not empty) when the error carries none (`omitempty`).

Encoding is `json.MarshalIndent(v, "", "  ")` plus one trailing newline. In the
default `table` format the same error prints as a single bare line on stderr —
never the JSON shape.

Format resolution is per-command: each command that supports `--format`
registers its own local flag, and `Execute()` reads the flag off whichever
command actually ran, so the failure envelope always uses the format the user
asked for. Exceptions that do not take `--format`: `get` uses `--json` (§2.2);
a `get` failure therefore always prints the bare table line.

### 2.2 Success payloads

Success JSON is not wrapped in an envelope: the stdout payload IS the result,
encoded with `json.MarshalIndent(v, "", "  ")` plus one trailing newline. All
`--format json` / `--json` commands follow this (`get`, `list`, `env`,
`audit`, `delete`, `diff`, `doctor`, `generate`, `history`, `llms`, `rotate`,
`set`, `sync`).

Determinism: encoding/json sorts map keys alphabetically and struct field order
is fixed, so identical inputs produce byte-identical JSON across runs. Payload
shapes are stable:

| Command | Shape |
|---------|-------|
| `get --json` | `{key, value}`; with `--with-metadata` adds `version`, `meta` (map keys sorted alphabetically). |
| `list --format json` | JSON array of items, sorted. |
| `env --format json` | Object mapping env-var name → value. |
| `llms --format json` | Fixed field set `{version, commands[], providers[], exit_codes{}, env_vars[], config_keys[]}` (§5). |

## 3. Stream discipline

- **stdout carries data only**: secret values, JSON payloads, lists, diffs,
  generated values. Nothing else.
- **stderr carries status**: warnings, progress, errors, remediation hints,
  structured logs (slog writes to stderr; level/format via `SKRET_LOG`,
  `SKRET_LOG_FORMAT`).
- `get` prints the value plus one trailing newline; `get --plain` prints the
  value with NO trailing newline for byte-exact capture into `$(...)` or
  redirection.
- `run` and `watch` pass the child's stdout/stderr through unmodified after
  skret's own status lines (stderr). skret MUST NOT interleave its own output
  into the child's stdout.
- Warnings MUST NOT change the exit code unless a §1 rule says otherwise.

## 4. Byte-exact guarantees

- A value stored via `set` (file, stdin, or argv) is stored verbatim and
  returned verbatim. skret MUST NOT trim, re-encode, normalize newlines, or
  expand anything in stored values.
- `run`/`env` inject secret values byte-exact: `$` is never expanded by skret.
  bcrypt hashes (`$2a$14$...`), `$`-bearing URLs, and shell-significant bytes
  survive verbatim into the child's environment. The child's own shell may
  expand them; skret does not.
- Key NAME → environment-variable NAME is the one documented transformation
  (`KeyToEnvName`): strip the path prefix, then map `/`, `-`, `=`, space,
  newline, CR to `_` and uppercase ASCII letters; non-ASCII bytes are
  preserved. Values are never touched by this mapping.
- `${KEY}` reference resolution applies ONLY at read time (`get`, `env`,
  `run`, `watch`) and ONLY to tokens whose payload is a valid
  environment-variable name. Values containing no valid reference token are
  returned byte-exact, always. Escapes suppress resolution:
  `\${NAME}` and `$${NAME}` stay byte-exact. Resolution failures (missing
  name, cycle, depth > 10) are exit 8 with a remediation hint.
- `--no-resolve` on read commands returns the raw stored value, skipping
  reference resolution entirely.
- `env` output formats (dotenv, json, yaml, export) round-trip byte-exact.

## 5. Non-interactive contract

- skret MUST NOT prompt unless stdin is a terminal. Where confirmation would
  be required, non-interactive contexts get a documented exit code plus a
  remediation hint instead of a prompt (e.g. `bootstrap` demands `--yes` when
  stdin is not a terminal).
- `skret delete` and `skret rollback` are the only mutation commands that
  prompt (y/N) by default; both skip it with `--confirm` or `-f`.
- Missing encryption key material for the local encrypted provider fails with
  exit 4 and a remediation hint; skret never prompts for keys in
  non-interactive mode.
- The interactive TUI is explicit opt-in (`skret browse`); no other command
  launches a UI. Every command MUST be safe to run with no TTY: no pagination,
  no confirmation dialogs, no "are you sure?".

## 6. llms.txt coverage

skret ships two llms.txt-convention surfaces, both names-only (secret names
and values are never included):

1. **`skret llms`** — prints a capability manifest an agent can paste into a
   session as in-context documentation. Generated live at run time from the
   actual cobra command tree (commands + flags), the provider registry, and
   the `pkg/skret` exit-code constants, so drift breaks the build or CI
   instead of silently diverging. `--format table` (default) renders
   deterministic text; `--format json` emits the fixed field set
   `{version, commands[], providers[], exit_codes{}, env_vars[],
   config_keys[]}` (§2.2). Output is byte-deterministic across runs, fully
   non-interactive, never reads config or key material, always exits 0.
2. **`https://skret.n24q02m.com/llms.txt`** — the published site manifest
   (`docs/public/llms.txt`), linking the agent guide, MCP server docs,
   value-fidelity guide, error-code table, and command guides.

## 7. Planned (not yet in code)

Audit result for v1 scope (§1–§6): **every contract surface above is
code-backed and CI-enforced** — no item in the exit-code table, the envelope,
stream discipline, byte-exact guarantees, or llms.txt coverage is aspirational.

Deferred to a future spec version:

- **LLM-driven agent e2e variant** — `tests/agent-e2e` is a scripted
  (keyless) harness today; the workflow explicitly reserves a gate
  (`vars.AGENT_E2E_LLM`) for an LLM-driven variant that is not implemented.
- **Envelope remediation coverage** — `remediation` is present only when an
  error carries a hint; a systematic per-code default-remediation table is
  not implemented and is not part of v1.

## 8. Versioning

- This file is versioned. Adding an exit code, changing the envelope shape, or
  altering a byte-exact or non-interactive guarantee requires a minor version
  bump here and a changelog entry.
- The `.skret.yaml` schema `version: "1"` is the only supported schema;
  anything else is exit 2.

### Changelog

- **1 — 2026-09-26**: Initial publication at repo root. Exit-code table,
  JSON error envelope, stream discipline, byte-exact guarantees,
  non-interactive contract, llms.txt coverage. Mirrors the rendered site spec
  v1.0.0; every section conformance-tested (`pkg/skret/spec_conformance_test.go`,
  `tests/agent-e2e`).
