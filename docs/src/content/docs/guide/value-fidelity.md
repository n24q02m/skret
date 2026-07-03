---
title: Value fidelity
description: "skret preserves secret values byte-for-byte across every command and format."
---

skret treats a secret value as opaque bytes. Reading a value back never
shell-expands, unquotes, or normalizes it. A value stored with `skret set`
round-trips byte-for-byte through every read path:

- **`skret get KEY --plain`** returns the exact bytes. (The default `get`,
  without `--plain`, appends one trailing newline for terminal readability —
  use `--plain` when the exact byte count matters, e.g. `skret get TOKEN --plain > token.bin`.)
- **`skret env --format=dotenv|json|yaml|export`** — each of the four dump
  formats is a lossless round-trip: parsing the output back with that
  format's own decoder yields the original value. The `export` form wraps
  the value in POSIX single quotes, so a shell that evaluates it reproduces
  the exact bytes with no expansion.
- **`skret template`** substitutes `${KEY}` with the literal value via a
  single substitution pass; the substituted value is never re-scanned for
  further `${...}` references, so a value containing `${OTHER}` stays
  literal. Use `$${KEY}` in the template source for a literal `${KEY}` in
  the output.
- **`skret sync --to=dotenv`** and **`skret import --from=dotenv`** share the
  same codec (`internal/dotenv`), so a value written by `sync` decodes back
  to the exact original bytes when read by `import`.

Values containing `$`, `=`, quotes, backslashes, newlines, tabs, and Unicode
are all preserved by every path above. `bcrypt` hashes (`$2a$14$...`),
connection strings with `$` in the password, and multi-line PEM keys/certs
all survive verbatim.

## Exception: `skret run` sanitizes control bytes

`skret run -- cmd` and `skret run --watch -- cmd` inject secrets as real
process environment variables via `execve`/`CreateProcess`, which imposes a
platform constraint the read paths above don't have: an environment value
cannot itself contain the byte that terminates it at the OS level. Before
injecting a value as an environment variable, `skret run` (`internal/exec.BuildEnv`)
removes any NUL byte (embedding one would make the underlying exec syscall
fail with "invalid argument"), removes any carriage return, and replaces
any line feed with a single space, to keep the process environment block
well-formed and to avoid corrupting tools that parse `env`-style output
line-by-line downstream.

This sanitization applies **only** to `run`/`watch` process injection. It
does not affect the byte-exact guarantees above: `skret get`, `skret env`,
`skret template`, and `skret sync`/`import` all preserve NUL bytes, CRs, and
embedded newlines untouched. If a value must retain these bytes inside a
running process, write it to a file with `skret get KEY --plain > file` (or
`skret template`) and have the process read the file instead of the
environment.

## Values with a leading dash

A value that starts with `-` (a PEM block, for example) looks like a flag
to skret's argument parser. Don't pass it as a bare positional argument;
use one of:

```bash
skret set KEY -- "-----BEGIN PRIVATE KEY-----..."
skret set KEY --from-stdin < key.pem
skret set KEY --from-file key.pem
```

## Reading a value from stdin or a file

`skret set KEY --from-stdin` reads the **entire** stdin stream — not just
its first line — so a multi-line value (a PEM key, a multi-line JSON blob)
survives with every embedded newline intact. `skret set KEY --from-file
path` reads the entire file the same way.

Both flags apply one deliberate, documented convenience: **all trailing
`\n` bytes are stripped** from the value before it's stored. This mirrors
POSIX `$(...)` command substitution, so `echo "value" | skret set KEY
--from-stdin` and a `key.txt` saved by a text editor (which appends a
trailing newline) both store `value`, not `value\n`. Only trailing `\n`
bytes are stripped:

- A single trailing newline, or several in a row, are all removed:
  `"value\n"` and `"value\n\n\n"` both store as `"value"`.
- A trailing `\r` (the first byte of a CRLF line ending) is content, not
  part of the stripped set, and survives: `"value\r\n"` stores as
  `"value\r"`.
- Embedded newlines — anywhere except a run of `\n` at the very end — are
  never touched: `"-----BEGIN-----\nabc\ndef\n-----END-----\n"` stores as
  `"-----BEGIN-----\nabc\ndef\n-----END-----"` (only the final newline is
  stripped; the three newlines inside the PEM body remain).
- A value with no trailing newline is stored exactly as given.

If a value's trailing newline(s) must be preserved verbatim, append an
extra sentinel byte before piping it in and strip the sentinel after
reading it back — `--from-stdin`/`--from-file` do not offer a
verbatim-trailing-newline mode.

## One platform limit: NUL bytes over the AWS SSM API

`skret set` sends a value to the AWS SSM provider exactly as given — skret
itself performs no NUL-byte filtering on the write path — but the SSM
`PutParameter` API may itself reject a value containing a NUL byte, since
it is not a printable string. This is an AWS API-level constraint, not a
skret design choice, and does not apply to the local provider (used for
`dev`/testing), which stores values as opaque YAML scalars with no such
restriction.
