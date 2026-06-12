---
title: Watch mode
description: "Auto-restart your command when secrets change, with no polling cost."
---

Auto-restart your command when secrets change, with no polling cost.

`skret run --watch` runs your command and restarts it whenever the secrets change upstream — so a rotated database password or a flipped feature flag reaches your process without you touching it.

```bash
skret run --watch -- npm start
```

## How it works

While your command runs, skret checks for changes on an interval (every 15s by default). Each check computes a no-decrypt **fingerprint** of the secret set rather than reading values. On AWS SSM the fingerprint is built from parameter **versions**, so a check issues **zero KMS Decrypt requests** — polling costs nothing. On the local provider, where reads are free, it compares values directly.

Only when the fingerprint changes does skret fetch the new values (one decrypt) and restart the command. On restart it prints:

```
[skret] secrets changed - restarting
```

Restarting terminates the running command (SIGTERM, then SIGKILL after a 5s grace on Unix; a hard kill on Windows) and relaunches it with the new environment.

Press Ctrl-C (or send SIGTERM to skret) to stop both skret and the command cleanly.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--watch` | `false` | Restart the command when secrets change |
| `--watch-interval` | `15s` | How often to check for secret changes |

`--watch-interval` accepts any Go duration (for example `30s`, `1m`, `5m`):

```bash
skret run --watch --watch-interval 30s -- ./server
```

## Notes

- **Secrets only, not liveness.** Watch mode restarts on *secret* changes, not on your command crashing. If the command exits on its own, skret exits with the command's exit code and does not relaunch it.
- **`skret run` is unchanged without `--watch`.** Plain `skret run -- <command>` runs once and forwards the exit code, exactly as before.
- **Values are never printed.** The fingerprint check reads versions, not values, and the restart line never includes secret contents.
