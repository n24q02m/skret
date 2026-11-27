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

| Tool                            | Kind  | Output                                                                                                   |
| ------------------------------- | ----- | -------------------------------------------------------------------------------------------------------- |
| `skret_list`                    | read  | JSON array of key names for an environment — names only, values structurally excluded                    |
| `skret_get`                     | read  | the raw value of one key — the only tool that returns values                                             |
| `skret_env`                     | read  | JSON `{environments: [...], default_env}` — the environments this server may access                      |
| `skret_status` / `skret_doctor` | read  | JSON health report: resolved env, provider, config file, write policy, tool/key policy when set, version |
| `skret_set`                     | write | create or update a secret (`{key, value, confirm}`)                                                      |
| `skret_delete`                  | write | delete a secret (`{key, confirm}`)                                                                       |
| `skret_rotate`                  | write | replace a value, recorded as a rotation in the audit trail (`{key, value, confirm}`)                     |

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

## Tool and key policy

Beyond the write gate and `allowed_envs`, the `mcp:` block can narrow which tools a client can call and which keys it can reach:

```yaml
mcp:
  allowed_tools: [skret_list, skret_get, skret_status] # optional: omit for every tool
  allowed_envs: [dev]
  allowed_keys: ["APP_*", "DATABASE_URL"] # optional: omit for every key
  denied_keys: ["*_ADMIN_*", "ROOT_*"] # optional: always wins over allowed_keys
  audit_log: .skret-mcp-audit.log # optional: see Session audit trail below
```

- **`allowed_tools`** lists the tools the server runs. Every entry must be a real tool name (a typo fails config load with the list of known names). It only narrows the set: a write tool still needs `allow_write: true`, and `skret_doctor` needs its own entry even though it is an alias of `skret_status`. A tool outside the list is refused on call. Once `allowed_tools` is set, `tools/list` shows exactly the tools a call can use: the listed tools, minus the write tools while `allow_write` is off. Without it, `tools/list` keeps listing all eight tools, write tools included, and a disabled write tool is refused only when called.
- **`allowed_keys`** and **`denied_keys`** are glob patterns matched against the whole key name with Go's [`path.Match`](https://pkg.go.dev/path#Match) syntax: `*` matches any run of characters except `/`, `?` matches one character, `[A-Z]` matches a character class, and `\` escapes a metacharacter. Matching is case-sensitive. A pattern `path.Match` cannot parse fails config load. A key that matches any `denied_keys` pattern is refused even when it also matches `allowed_keys`; with `allowed_keys` set, a key that matches none of its patterns is refused too.
- `skret_list` leaves out every key the key policy refuses, so a client only learns the names it may use. `skret_get`, `skret_set`, `skret_delete` and `skret_rotate` refuse such a key before the provider is called, so a refused key that exists and one that does not get the same answer.

All of these filters are checked together on every call, and a call that fails any of them is refused. A refusal is an error result that names the field to change, never a secret value:

```text
key "ROOT_TOKEN" is denied by mcp.denied_keys
remediation: the operator excluded this key from MCP access; it cannot be read or changed through this server
```

An empty or absent field keeps the earlier behaviour: every tool, every declared environment, every key. `skret_status` reports `tools`, `allowed_keys`, `denied_keys` and `audit_log` only when they are set, so a server without a tool or key policy reports the same fields as before.

## Session audit trail

Every `tools/call`, allowed or refused, writes exactly one JSON record. Records go to **stderr** and, when `mcp.audit_log` is set, are also appended to that file (created with mode `0600`; a relative path resolves against the directory of `.skret.yaml`). They are never written to stdout, which carries protocol messages only.

```json
{
  "timestamp": "2026-07-28T12:00:00.123456789Z",
  "event": "mcp_tool_call",
  "session_id": "4f6c0e2a9b1d4c7e8a3f5b2d1c0e9a8b",
  "tool": "skret_get",
  "env": "prod",
  "keys": ["DATA..._URL"],
  "decision": "deny",
  "reason": "env_not_allowed",
  "outcome": "error"
}
```

| Field        | Meaning                                                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `timestamp`  | RFC3339 UTC time of the call                                                                                                                                    |
| `event`      | always `mcp_tool_call`                                                                                                                                          |
| `session_id` | 128 random bits, hex; one per server process                                                                                                                    |
| `tool`       | tool name as requested (empty when the request had no name)                                                                                                     |
| `env`        | environment the call resolved to; omitted when the call was refused before an environment was picked                                                            |
| `keys`       | key names involved, masked (first and last 4 characters, or `***` for names of 8 characters or fewer); `["*"]` for `skret_list`; omitted for tools without keys |
| `decision`   | `allow` or `deny`                                                                                                                                               |
| `reason`     | deny reason, present only when `decision` is `deny`                                                                                                             |
| `outcome`    | `ok`, or `error` when the call returned an error result (a refusal, or an allowed call the provider failed)                                                     |

Deny reasons form a closed set, so you can alert on exact values:

| Reason              | Cause                                                               |
| ------------------- | ------------------------------------------------------------------- |
| `unknown_tool`      | the tool name is not one this server implements                     |
| `invalid_params`    | the `tools/call` params are malformed or have no tool name          |
| `tool_not_allowed`  | the tool is not in `mcp.allowed_tools`                              |
| `write_disabled`    | a write tool was called while `mcp.allow_write` is off              |
| `env_not_allowed`   | the environment is not in `mcp.allowed_envs`                        |
| `env_unknown`       | no environment was selected, or it is not declared in `.skret.yaml` |
| `key_denied`        | the key matches `mcp.denied_keys`                                   |
| `key_not_allowed`   | `mcp.allowed_keys` is set and the key matches none of its patterns  |
| `invalid_arguments` | a required argument is missing or not a string                      |
| `confirm_required`  | a write call did not carry `"confirm": true`                        |

The stderr copy is best effort. The file copy is not: if `mcp.audit_log` cannot be written at startup the server refuses to start, and if a later append fails the call returns an error result instead of its output. A write tool may already have changed the store by then, which the error text says.

## Local provider read trail

When the selected environment uses the **local provider**, every MCP read (`skret_get`, `skret_list`) also appends an `mcp_read` line to the same JSONL audit trail that mutations use (`.skret-audit.log` next to the secrets file, or the environment's `audit_log` override). If that trail cannot be written, the read fails instead of silently skipping the entry. Values are structurally excluded from audit entries — only key names, environment, actor (`SKRET_ACTOR` or OS user), and timestamp are recorded. Cloud providers record access through their own audit systems (`skret audit` reads AWS CloudTrail).

## Redaction

Secret values reach a client only as the result of a successful `skret_get`. Every other text the server produces passes through redaction first: protocol error messages, error results, the session audit trail, and stderr diagnostics, including those logged by the provider packages underneath. Redaction replaces with `[REDACTED]`:

- every secret value loaded during the session: values read by `skret_get`, every value `skret_list` loaded from the provider, and every value passed to a write tool (registered before the call is checked, so a refused write counts too). Values shorter than 4 characters are not redacted by value, because they collide with ordinary words and numbers.
- secret-shaped text even when it was never loaded: `password=`/`token=`/`key=`-style assignments, common token prefixes, AWS access key ids, and long base64-like runs. A long run like that inside an error message, such as a deep file path, can be masked too.

So a client that sends a secret value back as a key, tool, environment or method name gets an error that shows `[REDACTED]` in its place.

## Protocol versions

The server speaks MCP `2026-07-28`, `2025-06-18`, `2025-03-26` and `2024-11-05`.

- **2024-11-05 to 2025-06-18** negotiate once through `initialize` and then send plain requests. `initialize` answers with the client's version when it is one of these three, and with `2025-06-18` for any other value.
- **2026-07-28** has no `initialize` handshake. Each request names the version in `params._meta["io.modelcontextprotocol/protocolVersion"]` and must carry `params._meta["io.modelcontextprotocol/clientCapabilities"]` as an object. The server answers `server/discover` with its supported versions and capabilities, marks every result `"resultType": "complete"`, and reports its identity in `_meta["io.modelcontextprotocol/serverInfo"]`. List and discovery results carry `"ttlMs": 0` and `"cacheScope": "private"`, because the tool set depends on this server's policy.
- A request whose `_meta` names an older supported version is served with that version's rules. A version the server does not support is refused with error `-32022` and `data: {"supported": [...], "requested": "..."}`.
- A request without `_meta["io.modelcontextprotocol/protocolVersion"]` is served exactly as before 2026-07-28 support existed. In particular, `server/discover` sent without it gets the usual method-not-found error.

Over Streamable HTTP, a `2026-07-28` request must also send `MCP-Protocol-Version` matching the body, `Mcp-Method` matching the method (notifications included), and for `tools/call` an `Mcp-Name` matching the tool name. A value may be sent base64-encoded as `=?base64?...?=`. A missing or mismatched header is refused with HTTP 400 and error `-32020`, before the request runs. For these requests, protocol errors use HTTP 404 for an unknown method and 400 otherwise, and notifications get 202. The server keeps no session state, so `Mcp-Session-Id` is ignored. Requests without per-request `_meta` keep the earlier transport rules.

The server implements only the parts of `2026-07-28` a tools-only server needs: it offers no resources or prompts, and it returns every result complete in a single response.

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

Diagnostics and session audit records go to stderr only; stdout carries protocol messages exclusively.
