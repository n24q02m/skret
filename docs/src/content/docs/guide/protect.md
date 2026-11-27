---
title: Protect
description: "Block .env files and plaintext credentials from being committed, in any repository, with no config."
---

Block `.env` files and plaintext credentials from being committed.

```bash
skret protect
```

With no arguments, this checks the files staged for the next commit, reading their staged content from the git index. Each problem is reported as a `FILE  LINE  RULE` row and the command exits with code **10**. When nothing is found it prints `No plaintext secrets found.` to stderr and exits 0.

## How it differs from `skret scan`

[`skret scan`](/guide/scan/) looks for your **real managed values**: it loads the secrets skret manages and searches your files for them. It needs a `.skret.yaml` and access to the provider, and it only finds secrets skret manages.

`skret protect` looks for **secret shapes**: dotenv file names and well-known credential formats. It needs no `.skret.yaml`, no provider and no credentials, so it runs in any repository, including ones that do not use skret for their secrets. The trade-off is that it only finds credentials with a recognizable shape.

The two complement each other: `protect` catches a pasted token or a `.env` file skret has never seen, `scan` catches a managed value whatever it looks like.

Output names the **file**, the **line** and the **rule**. The matched text is never printed, so the output is safe to keep in CI logs.

## What it flags

| Rule                          | Flags                                                                                                                                                                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env-file`                    | A dotenv file: `.env`, `.env.<name>`, `.env-<name>`, `.env_<name>` or `<name>.env`, in any case. Templates ending in `.example`, `.sample`, `.template` or `.dist` are allowed, but their content is still checked. `.envrc` is not a dotenv file. The line shows as `-`. |
| `sk-api-key`                  | `sk-` API keys of 20 or more letters and digits                                                                                                                                                                                                                           |
| `doppler-service-token`       | Doppler service tokens (`dp.st.`)                                                                                                                                                                                                                                         |
| `github-pat`                  | GitHub classic personal access tokens (`ghp_`)                                                                                                                                                                                                                            |
| `aws-access-key-id`           | AWS access key IDs (`AKIA`)                                                                                                                                                                                                                                               |
| `github-token`                | GitHub OAuth, user-to-server, server-to-server and refresh tokens (`gho_`, `ghu_`, `ghs_`, `ghr_`)                                                                                                                                                                        |
| `github-fine-grained-pat`     | GitHub fine-grained personal access tokens (`github_pat_`)                                                                                                                                                                                                                |
| `aws-temporary-access-key-id` | AWS temporary (STS) access key IDs (`ASIA`)                                                                                                                                                                                                                               |
| `sk-scoped-api-key`           | Scoped `sk-<scope>-` API keys (for example `sk-proj-`)                                                                                                                                                                                                                    |
| `slack-token`                 | Slack tokens (`xoxb-`, `xoxp-`, ...)                                                                                                                                                                                                                                      |
| `slack-webhook`               | Slack incoming webhook URLs                                                                                                                                                                                                                                               |
| `stripe-live-key`             | Stripe live secret and restricted keys (`sk_live_`, `rk_live_`)                                                                                                                                                                                                           |
| `google-api-key`              | Google API keys (`AIza`)                                                                                                                                                                                                                                                  |
| `gitlab-pat`                  | GitLab personal access tokens (`glpat-`)                                                                                                                                                                                                                                  |
| `npm-token`                   | npm access tokens (`npm_`)                                                                                                                                                                                                                                                |
| `pypi-token`                  | PyPI API tokens (`pypi-`)                                                                                                                                                                                                                                                 |
| `private-key`                 | PEM private key headers (`-----BEGIN ... PRIVATE KEY-----`)                                                                                                                                                                                                               |
| `age-secret-key`              | age secret keys (`AGE-SECRET-KEY-1`)                                                                                                                                                                                                                                      |

The first four token rules are the patterns skret uses to redact its own logs; the rest are added for `protect`. Every token rule has a fixed prefix and a minimum length, and only matches at the start of a word, so ordinary code and prose do not trigger it.

## Pre-commit hook

This repository publishes a [pre-commit](https://pre-commit.com) hook that works in any repository, whatever its language (Go, Python, TypeScript, ...). Add it to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/n24q02m/skret
    rev: vX.Y.Z # a skret release tag
    hooks:
      - id: skret-protect
```

Two hooks are available:

| Hook                   | `language` | What it runs                                                                                                                                                                                                                                                                                            |
| ---------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `skret-protect`        | `golang`   | pre-commit builds skret from the pinned `rev`, so the hook always matches `rev` and nothing has to be installed first. If `go` is not on `PATH`, pre-commit (3.0 or newer) downloads a Go toolchain into its own cache. The first run builds skret and takes a few minutes; later runs reuse the build. |
| `skret-protect-system` | `system`   | Runs the `skret` already on `PATH` ([installed](/guide/installation/) with Homebrew, Scoop, `install.sh`, ...). Nothing is built, but the version is whatever is installed, not `rev`.                                                                                                                  |

Use `skret-protect` by default, because its version is pinned in your config. Use `skret-protect-system` when every machine that runs the hook already has skret, or when the build time matters (for example in a short-lived CI container).

Both hooks pass the staged file names to `skret protect`. pre-commit stashes unstaged changes before it runs hooks, so the files on disk hold exactly what will be committed. Hook arguments are passed through, for example:

```yaml
- id: skret-protect
  args: ["--allow", "testdata/"]
```

To run the check without pre-commit, call it from `.git/hooks/pre-commit`:

```sh
#!/bin/sh
skret protect
```

## Options

### `[path...]`

Check these files instead of the staged ones. A directory covers the files under it that git would let you commit (tracked and untracked, minus `.gitignore`), or every file when it is not inside a git repository. Binary and oversize files are checked by name only.

```bash
skret protect .env.production config/
```

### `--allow`

Skip paths matching a pattern (repeatable). A pattern without `/` matches the file name at any depth (`*.pem`), a pattern ending in `/` matches everything under a directory of that name at any depth (`testdata/`), and any other pattern matches the whole path (`docs/*.md`).

```bash
skret protect --allow 'testdata/' --allow '*.pem.example'
```

To keep one intentional line (a documented example token, a test fixture), put `skret:allow` anywhere on that line instead:

```go
const exampleKeyID = "AKIAEXAMPLEEXAMPLE00" // skret:allow
```

### `--strict`

Also apply the generic heuristics skret uses to redact its own logs: `password=`, `secret=`, `token=`, `key=`, `api_key=` and `auth=` assignments (`secret-assignment`), and runs of 40 or more base64-like characters (`base64-blob`). These catch more, but also flag hashes, lockfiles and placeholders, so expect to need `--allow`.

```bash
skret protect --strict
```

### `--format`

Output format: `table` (default) or `json`. JSON is an array of `{file, line, rule}` objects, where `line` is `0` for an `env-file` finding. An empty result is `[]`.

```bash
skret protect --format json
```

## Exit codes

| Code | When                                                                                   |
| ---- | -------------------------------------------------------------------------------------- |
| 0    | Nothing found                                                                          |
| 1    | The staged files could not be read (for example, not inside a git repository)          |
| 8    | Invalid flag: unknown `--format`, bad `--allow` pattern, or a path that does not exist |
| 10   | At least one finding                                                                   |

See [error codes](/reference/error-codes/) for the full table.
