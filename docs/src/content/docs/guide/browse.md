---
title: Browse
description: "Browse secrets in an interactive terminal UI, revealing values on demand."
---

Browse your secrets in a full-screen, interactive terminal UI. Values stay masked until you reveal them.

```bash
skret browse
```

## Keys

| Key | Action |
|-----|--------|
| Up / Down | Move the selection |
| `/` | Filter the list by key name |
| Enter (or Space) | Reveal or hide the selected value |
| `q` (or Esc / Ctrl-C) | Quit |

## How it works

The list of keys comes from a **names-only listing** that decrypts nothing, so opening `skret browse` and scrolling around costs nothing — no KMS Decrypt requests.

Each value is **masked** (`••••••••`) until you reveal it. The first time you reveal a key, skret fetches and decrypts that **one** secret on demand (one decrypt per revealed secret); the value is cached, so revealing it again is free. Press reveal again to hide it.

## Notes

`skret browse` needs an **interactive terminal**. If stdout is piped or redirected (for example in CI), it prints `browse requires an interactive terminal` and exits non-zero (code `8`) rather than emitting control codes.

It is **read-only** — browsing never changes a secret. Use `skret set` to create or update a secret and `skret delete` to remove one.
