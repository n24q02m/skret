---
title: Shell completion
description: "Tab-complete real secret key names with no decryption cost."
---

Tab-complete real secret key names with no decryption cost.

`skret get <TAB>` completes the actual secret keys under the configured environment. The same dynamic completion is wired onto `skret delete`, `skret history`, and `skret rollback` — every command whose first argument is a secret key.

```bash
skret get DB<TAB>
# expands to:
skret get DB_URL
```

## Setup

Load the completion script for your shell. `skret completion <shell>` prints a script to stdout; source it (or install it where your shell looks for completions).

```bash
# bash
source <(skret completion bash)

# zsh
source <(skret completion zsh)

# fish
skret completion fish | source

# powershell
skret completion powershell | Out-String | Invoke-Expression
```

For persistence, add the line to your shell rc file or drop the generated script in the shell's completions directory. For example, zsh:

```bash
# one-off (current shell)
source <(skret completion zsh)

# persistent: write into a directory on $fpath
skret completion zsh > "${fpath[1]}/_skret"
```

## No KMS / no decryption cost

Key-name completion calls a names-only listing that does **not** decrypt any value. On AWS SSM this lists parameters with decryption disabled, so a `<TAB>` issues **zero KMS Decrypt requests** — it is free of KMS cost. That matters for SSM SecureString users, where every decrypted value is a billed KMS Decrypt call.

Plain `skret list` uses the same names-only listing, so listing your keys also costs nothing to decrypt:

```bash
skret list            # KEY only — no decryption
skret list --values   # KEY + VERSION + VALUE — decrypts
```

Because plain `skret list` never decrypts, it prints the **KEY column only**. Use `skret list --values` when you need KEY, VERSION, and VALUE.

## Security

Completion never prints secret values — only key names. On any provider or authentication error it silently yields no candidates rather than printing errors into your shell, so a missing credential or a misconfigured path produces an empty completion, never noise.
