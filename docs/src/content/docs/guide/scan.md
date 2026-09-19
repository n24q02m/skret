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

### `--history`

Scan committed blob content across git history instead of the working tree — the check for "did this value ever get committed?". Each unique blob is reported once, at the commit that introduced it, so a value carried forward unchanged is attributed to its first commit rather than re-reported.

```bash
skret scan --history
```

Output rows gain a `COMMIT` column (`commit` in JSON), and `file` is the repo-relative path as git reports it. Because values are matched against real blob content — not patches — this catches values committed and later removed, and reports the exact commit to scrub.

The walk is bounded so a large repository cannot turn into an unbounded job: `--max-count` caps how many commits are visited (default `1000`) and `--since` accepts any git date expression. A repository with no commits scans empty. Binary and oversize blobs are skipped, and blob content streams one object at a time through a single `git cat-file --batch` process, so memory stays flat regardless of history size.

### `--since`

With `--history`, only scan commits newer than this git date expression (e.g. `"2 weeks ago"` or `2026-01-01`).

```bash
skret scan --history --since="2 weeks ago"
```

### `--max-count`

With `--history`, cap the number of commits walked (default `1000`).

```bash
skret scan --history --max-count=200
```

### `--format`

Output format: `table` (default) or `json`. JSON is an array of `{key, file, line}` objects — still no values. With `--history`, each object also carries a `commit` field.

```bash
skret scan --format json
```

### `--min-length`

Ignore managed values shorter than this length (default `5`). This avoids trivial matches on short values such as `1` or `true`.

```bash
skret scan --min-length 8
```

## Scope

Without `--history`, `skret scan` inspects the current working tree (or staged content with `--staged`) — not the past. With `--history`, it walks committed blob content (bounded by `--max-count`/`--since`) and reports each managed value at the commit that introduced it, so a value that was committed and later removed is still caught.
