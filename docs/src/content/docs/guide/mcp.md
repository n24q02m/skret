---
title: MCP server (skret mcp)
description: "Expose skret to Claude Code, OMP, and other MCP clients over stdio or Streamable HTTP — read-only by default, writes gated behind config."
---

`skret mcp` is the built-in MCP (Model Context Protocol) subcommand of `skret`: it discovers the same `.skret.yaml` as the CLI and serves tools over stdio or Streamable HTTP (`/mcp`, `/healthz`).

Design rule: **secret values move only through an explicit `skret_get` call.** Everything else exposes names, environments, or health — never values.

## Install

`skret mcp` is built into the `skret` binary distributed via Homebrew, Scoop, GitHub release archives, and the Docker image. Verify with:

```bash
skret mcp --help
```

## Tools

| Tool                            | Kind  | Output                                                                                |
| ------------------------------- | ----- | ------------------------------------------------------------------------------------- |
| `skret_list`                    | read  | JSON array of key names for an environment — names only, values structurally excluded |
| `skret_get`                     | read  | the raw value of one key — the only tool that returns values                          |
| `skret_env`                     | read  | JSON `{environments: [...], default_env}` — the environments this server may access   |
| `skret_status` / `skret_doctor` | read  | JSON health report: resolved env, provider, config file, write policy, version        |
| `skret_set`                     | write | create or update a secret (`{key, value, confirm}`)                                   |
| `skret_delete`                  | write | delete a secret (`{key, confirm}`)                                                    |
| `skret_rotate`                  | write | replace a value, recorded as a rotation in the audit trail (`{key, value, confirm}`)  |

Every read tool (and every write tool) accepts an optional `env` argument to select a different environment; without it the server uses the environment resolved at startup (`--env`, else `default_env`, else the single declared environment).

## Write gate (default off)

Write tools are **disabled by default**. A `skret_set`/`skret_delete`/`skret_rotate` call against a server without `mcp.allow_write` returns an error result naming the exact config field:

```text
skret_set: write operations are disabled for this skret-mcp server
remediation: set mcp.allow_write: true in .skret.yaml (then restart the server) if the operator intends to allow secret mutation through MCP
```

To enable writes, opt in per project in `.skret.yaml`:

```yaml
version: "1"
default_env: dev

mcp:
  allow_write: true # default false
  allowed_envs: [dev] # optional: restrict which envs MCP may touch

environments:
  dev:
    provider: local
    file: .secrets.dev.yaml
```

`allow_write` authorizes the _server_; each individual write call must additionally carry a per-call `"confirm": true` argument (the MCP mirror of the CLI `--confirm` flag). A call without it is refused and nothing is mutated:

```text
skret_delete: per-call confirmation missing
remediation: add "confirm": true to the tool arguments (mirrors the CLI --confirm flag); nothing was mutated
```

The `mcp:` block is optional. With no `allowed_envs`, the server may access every declared environment; with the filter set, requests for any other environment fail with a remediation pointing at the filter. The `--env` chosen at startup is validated the same way, so a misconfigured server refuses to start rather than serving an environment it is not allowed to touch.

## Audit trail

When the selected environment uses the **local provider**, every MCP read (`skret_get`, `skret_list`) appends an `mcp_read` line to the same JSONL audit trail that mutations use (`.skret-audit.log` next to the secrets file, or the `audit_log` override). If the trail cannot be written, the read fails instead of silently skipping the entry. Values are structurally excluded from audit entries — only key names, environment, actor (`SKRET_ACTOR` or OS user), and timestamp are recorded. Cloud providers record access through their own audit systems (`skret audit` reads AWS CloudTrail).

## Wiring up a client

`skret mcp` speaks newline-delimited JSON-RPC 2.0 on stdin/stdout by default (`--transport stdio`), or Streamable HTTP (`--transport http --addr 127.0.0.1:8787`, with optional `--token` / `SKRET_MCP_TOKEN` required for non-loopback binds). Point `--workdir` (or the client's own working directory, by leaving it off) at the project that owns the `.skret.yaml`.

### Claude Code

```bash
claude mcp add skret -- skret mcp --workdir /path/to/project
```

or in the project's `.mcp.json`:

```json
{
  "mcpServers": {
    "skret": {
      "command": "skret",
      "args": ["mcp", "--workdir", "."]
    }
  }
}
```

### OMP

```toml
[mcp.servers.skret]
command = "skret"
args = ["mcp", "--workdir", "."]
```

### Other clients

Any client that supports stdio or Streamable HTTP MCP servers works the same way: command `skret`, args `["mcp", "--workdir", "<project>"]`. Relative paths inside `.skret.yaml` (like `file: .secrets.dev.yaml`) resolve against the config's own directory, so the server can be launched from anywhere.

## Flags

| Flag                        | Default           | Description                                                           |
| --------------------------- | ----------------- | --------------------------------------------------------------------- |
| `--workdir <dir>`           | current directory | Where to discover `.skret.yaml`                                       |
| `--transport <stdio\|http>` | `stdio`           | MCP transport mode                                                    |
| `--addr <host:port>`        | `127.0.0.1:8787`  | HTTP listen address for `--transport=http`                            |
| `--token <token>`           | `SKRET_MCP_TOKEN` | Bearer token for `--transport=http` (required for non-loopback binds) |
| `--env <name>`              | `default_env`     | Pin the environment (must satisfy `allowed_envs`)                     |
| `--provider <name>`         | config            | Override the provider                                                 |
| `--path <prefix>`           | config            | Override the secret path prefix                                       |

Diagnostics go to stderr only; stdout carries protocol messages exclusively.
