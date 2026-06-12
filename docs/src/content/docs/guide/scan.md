---
title: Scan
description: "Find your managed secret values leaked into tracked files."
---

Find your managed secret values leaked into tracked files.

```bash
skret scan
```

This lists your managed secrets once, then checks whether any of their values appear in your tracked files. If a value shows up, the leak is reported as a `KEY  FILE  LINE` row and the command exits non-zero.

## How it works

`skret scan` matches your **real managed values** — the secrets skret manages for the current environment — against the contents of your files. Because it looks for the actual values, it does not guess from patterns, so there are no false positives from strings that merely "look like a key". The trade-off is that it only finds the secrets skret manages.

The file set is your **git-tracked files** (`git ls-files`), so it respects `.gitignore`. If the directory is not a git repository, skret walks the tree instead, skipping `.git/`. Binary and oversize files are skipped.

Output reports the **key name** and **file:line** of each match — the secret value is never printed. On any finding the command exits with code **10**, so CI jobs and pre-commit hooks fail when a managed secret would be committed. When nothing is found it exits 0.

## Pre-commit hook

Run the scan against staged content so a leak blocks the commit. Add this to `.git/hooks/pre-commit` and make it executable:

```sh
#!/bin/sh
skret scan --staged || {
  echo "A managed secret would be committed. Aborting." >&2
  exit 1
}
```

`--staged` scans only the staged files (`git diff --cached`), which is what you want in a commit hook.

## Options

### `--staged`

Scan only staged files instead of all tracked files. Intended for pre-commit hooks.

```bash
skret scan --staged
```

### `--format`

Output format: `table` (default) or `json`. JSON is an array of `{key, file, line}` objects — still no values.

```bash
skret scan --format json
```

### `--min-length`

Ignore managed values shorter than this length (default `5`). This avoids trivial matches on short values such as `1` or `true`.

```bash
skret scan --min-length 8
```

## Scope

`skret scan` only inspects the current working tree (or staged content with `--staged`). It does not scan past git history — a value that was committed and later removed will not be reported.
