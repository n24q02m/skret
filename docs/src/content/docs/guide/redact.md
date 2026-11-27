---
title: Redacted output
description: "Run a command with secrets injected and mask them in its stdout and stderr before they reach a terminal, a CI log or an agent."
---

Run a command with secrets injected, and mask those secrets in everything it prints.

```bash
skret run --redact -- ./deploy.sh
```

Without `--redact`, `skret run` hands the terminal straight to the command, and anything it prints, including a secret it echoes by mistake, ends up in your scrollback, your CI log or an agent's context. With `--redact`, the command's stdout and stderr pass through a filter first, and every secret is replaced with `[REDACTED]`.

## What is masked

Every secret `skret run` loaded for the environment, in each form the command is likely to print it:

- the value as stored, and as injected into the environment (where a newline becomes a space; see [value fidelity](/guide/value-fidelity/));
- the value as quoted into an error message or a JSON string, with quotes, backslashes and newlines escaped (`pa\"ss`, `line1\nline2`);
- each line of a multi-line value (a PEM key, a certificate), on its own, and the whole value with `\n` or `\r\n` line endings;
- standard and URL-safe base64, with and without padding, including when the value is encoded as part of a longer string;
- URL query and path escaping (`p%40ss%2Fword`).

On top of that, the output goes through the patterns skret uses to redact its own logs, so token-shaped strings that skret does not manage are masked too: `password=`, `secret=`, `token=`, `key=`, `api_key=` and `auth=` assignments (the key is kept, the value is masked), `sk-` API keys, Doppler service tokens, GitHub `ghp_` tokens, AWS access key IDs, and runs of 40 or more base64-like characters.

The last pattern also matches things that are not secrets, such as 40-character git commit SHAs and long hashes. Expect those to show as `[REDACTED]` in redacted output.

## Short values

Values shorter than `--redact-min-length` bytes (default `4`, the same minimum skret uses when it masks known values in its own logs) are not masked, because masking `80`, `on` or `1` would garble unrelated output. skret names the variables it skipped on stderr before the command starts:

```text
skret: --redact: 1 value(s) shorter than 4 bytes are not masked: APP_PORT
```

Lower the threshold if a short value really is secret:

```bash
skret run --redact --redact-min-length 3 -- ./deploy.sh
```

## Streaming and buffering

The filter streams: output is passed on as the command writes it. It only holds bytes back while they could still be the start of a secret or of a token pattern:

- at most the length of the longest secret (or encoded form) minus one byte, while those bytes are still a prefix of one;
- the text after the last whitespace character, because no token pattern spans whitespace, up to 64 KiB.

A newline therefore flushes ordinary output, and everything still held is flushed when the command exits, so the last line is never lost. The result does not depend on how the command split its writes: a secret written across two `write()` calls is masked exactly like one written at once, and no byte is dropped or repeated. A single unbroken run longer than 64 KiB is flushed in pieces, so a token pattern that straddles a piece boundary may be masked in two parts, or (for the base64-like pattern) not at all; managed values are still masked across the boundary.

## What changes for the command

- **No terminal.** The command's stdout and stderr are pipes, not the terminal, so programs that check for a TTY may turn off colour, progress bars or interactive prompts, and some switch from line to block buffering. Many tools have a flag to force colour (`--color=always`). stdin is still the terminal.
- **Separate streams.** stdout and stderr are filtered separately and stay separate, but when the command writes to both at nearly the same time, the two can reach a shared terminal in a slightly different order.
- **Exit code.** skret exits with the command's exit code. When the command exits non-zero, skret also prints one status line such as `exit status 3` to stderr. On Unix, a command killed by a signal exits as `128 + signal`, the code a shell reports.
- **Signals.** `SIGTERM`, `SIGUSR1` and `SIGUSR2` sent to skret are always relayed to the command, and skret waits for it to exit. `SIGINT`, `SIGQUIT` and `SIGHUP` are relayed only when skret is not in the terminal's foreground process group. In the foreground, the terminal already delivers Ctrl+C, `Ctrl+\` and a hangup to the command itself, and relaying them as well would make an interactive command receive each one twice. The trade-off: while skret runs in the foreground, `SIGINT`, `SIGQUIT` or `SIGHUP` sent with `kill` to skret's own PID is **not** relayed, and the command keeps running. To stop the command from a script, send `SIGTERM` (`kill <pid>`), which is relayed, or signal the whole process group (`kill -INT -<pgid>`), which reaches skret and the command together. On Windows the console delivers Ctrl+C and Ctrl+Break to the command directly.
- **Text output only.** The filter is meant for text. Binary output, such as `tar c` or an image written to stdout, is corrupted wherever a byte sequence happens to match a secret or a pattern, so do not pipe binary data through `--redact`. In text, long paths and hashes such as git SHAs can match the base64-like pattern and show as `[REDACTED]`.
- **Child processes.** If the command starts a background process that keeps its output open after the command exits, skret waits up to 5 seconds for that output, then exits with the command's code.

`--redact` cannot be combined with `--watch`.

## When to use it

`--redact` is a safety net for output that is read by someone or something other than you: CI logs, shared terminals, screen recordings, and AI agents running commands for you. It is not a guarantee: a command can still transform a secret (hash it, reverse it, print it a character at a time across lines) into a form the filter does not recognize. Keep secrets out of output in the first place, and use `--redact` to catch what slips through.

Pair it with [`skret protect`](/guide/protect/) in a pre-commit hook so plaintext credentials do not reach the repository either.
