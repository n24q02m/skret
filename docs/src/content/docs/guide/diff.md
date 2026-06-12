---
title: Diff
description: "Compare two secret sets and detect drift without printing secret values."
---

Compare two secret sets and detect drift without printing secret values.

`skret diff` supports three pairings: environment vs environment, environment vs dotenv file, and environment vs GitHub Actions secrets.

## Pairings

### Environment vs environment

```bash
skret diff staging prod
```

Compares every key present in either environment and reports which keys are only in one side, which have changed values, and which are identical.

### Environment vs dotenv file

```bash
skret diff prod --dotenv .env.local
```

Useful when migrating from a local `.env` file to a cloud-backed environment, or before a `skret import` run to preview what will change.

### Environment vs GitHub Actions secrets

```bash
export GITHUB_TOKEN=ghp_xxx
skret diff prod --to=github --github-repo=myorg/myapp
```

GitHub Actions secrets are write-only: their values cannot be read back through the API. This pairing therefore reports **presence only** — keys that exist in the environment but not in the repository, and vice versa. Changed values cannot be detected and are listed under a `cannot compare values` note in the output.

## Value safety

Secret values are **never printed** in any output mode.

The default table output shows only key names and their status:

| Status | Meaning |
|--------|---------|
| `only_a` | Key exists in A only |
| `only_b` | Key exists in B only |
| `changed` | Key exists in both; values differ |
| `same` | Key exists in both; values match |
| `unknown` | Cannot compare (e.g. write-only GitHub secret) |

### `--show-hash`

When you need to confirm which value is newer without revealing either value, pass `--show-hash`:

```bash
skret diff staging prod --show-hash
```

The output appends a `sha256[:8]` fingerprint for each side of a `changed` row:

```
KEY             STATUS   A           B
DATABASE_URL    changed  sha=a1b2c3d4 sha=e5f6a7b8
```

The eight-character prefix is enough to confirm that two values differ (or that a new value matches a known good hash) without disclosing the actual secret.

## JSON output

Pass `--format json` to get machine-readable output:

```bash
skret diff staging prod --format json
```

The JSON object has the following shape:

```json
{
  "a": "env:staging",
  "b": "env:prod",
  "only_a": ["KEY_ONLY_IN_STAGING"],
  "only_b": ["KEY_ONLY_IN_PROD"],
  "changed": ["DATABASE_URL", "REDIS_URL"],
  "unknown": [],
  "same_count": 14
}
```

| Field | Type | Description |
|-------|------|-------------|
| `a` | string | Label for the first side |
| `b` | string | Label for the second side |
| `only_a` | string array | Keys present in A only |
| `only_b` | string array | Keys present in B only |
| `changed` | string array | Keys present in both with differing values |
| `unknown` | string array | Keys that could not be compared (write-only side) |
| `same_count` | number | Count of keys that are identical on both sides |

## CI drift gate with `--exit-code`

`--exit-code` causes `skret diff` to exit with a non-zero status code when any drift is found (same semantics as `git diff --exit-code`). Use it to fail a workflow when environments have diverged:

```yaml
name: Drift check
on:
  schedule:
    - cron: '0 8 * * *'   # Daily 8am

permissions:
  id-token: write
  contents: read

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/skret-github-actions
          aws-region: us-east-1

      - name: Install skret
        run: |
          curl -fsSL https://github.com/n24q02m/skret/releases/latest/download/skret_linux_amd64.tar.gz | tar xz
          sudo mv skret /usr/local/bin/

      - name: Check for drift between staging and prod
        run: skret diff staging prod --exit-code
```

The step fails — and the workflow turns red — if any key differs between environments. Combine with `--format json` to parse the output in a subsequent step if you want to post a summary elsewhere.

## Raw provider paths

A positional argument that starts with `/` is treated as a raw provider path rather than an environment name from `.skret.yaml`. This lets you compare two paths ad hoc without adding them to your config file:

```bash
skret diff /myapp/staging /myapp/prod
skret diff /myapp/prod --dotenv .env.backup
```

The label shown in the output reflects the path:

```
path:/myapp/staging vs path:/myapp/prod
```
