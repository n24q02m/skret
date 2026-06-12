---
title: Template
description: "Render a template file, substituting ${KEY} placeholders with secret values."
---

Render a template file, substituting `${KEY}` placeholders with secret values.

`skret template` reads a file, replaces every `${KEY}` token with the matching secret from the configured provider, and writes the result to stdout or to a file.

## Basic usage

```bash
skret template nginx.conf.tpl
```

Write to a file instead of stdout:

```bash
skret template nginx.conf.tpl --output nginx.conf
# short form
skret template nginx.conf.tpl -o nginx.conf
```

## Environment resolution

`skret template` resolves the secret environment the same way `skret run` and `skret env` do, in this order:

1. **`.skret.yaml`** in the current directory (or the nearest parent). The `env` field selects which path to read.
2. **`-e` / `--env` flag** overrides the environment from the config file.
3. **`--path` flag** supplies a raw provider path directly, bypassing `.skret.yaml` altogether.

Examples:

```bash
# Use the default environment from .skret.yaml
skret template app.conf.tpl -o app.conf

# Override the environment
skret template app.conf.tpl --env staging -o app.conf

# Use a raw path without a config file
skret template app.conf.tpl --path /myapp/prod -o app.conf
```

## Substitution syntax: braces required

Only `${KEY}` tokens are substituted. Bare `$VAR` references are left untouched.

This is intentional. Template files are often nginx configs, shell scripts, or other formats where bare `$variable` syntax has meaning that must not be disturbed:

```nginx
# nginx.conf.tpl
server {
    listen 80;
    server_name $host;          # left intact — nginx variable
    root $document_root;        # left intact — nginx variable

    location / {
        proxy_pass ${UPSTREAM_URL};   # substituted — skret secret
    }
}
```

After rendering, `$host` and `$document_root` remain as-is for nginx to resolve at request time, while `${UPSTREAM_URL}` is replaced with the secret value.

## Escaping literal `${...}`

Use `$$` to emit a single literal `$`. This lets you write `$${VAR}` in the template and get the literal text `${VAR}` in the output — useful when the file is itself a template that will be processed later (for example, a shell `${VAR:-default}` expression):

```bash
# Template source
echo 'export URL=${UPSTREAM_URL}'  >  deploy.sh.tpl
echo 'fallback=$${REDIS_URL:-localhost}' >> deploy.sh.tpl

# After rendering (UPSTREAM_URL=https://api.example.com)
#   export URL=https://api.example.com
#   fallback=${REDIS_URL:-localhost}
skret template deploy.sh.tpl
```

## Missing keys fail loudly

If any `${KEY}` in the template has no matching secret, `skret template` exits non-zero without writing any output and prints the names of the missing keys:

```
template: undefined keys: UPSTREAM_URL, DB_DSN
```

This prevents a partially-rendered file from silently reaching disk. Fix the gap — add the missing secret or remove the placeholder — then re-run.

## `--output` / `-o`

When `--output` is given, the rendered content is written to the named file with permissions `0600`. The restrictive mode is deliberate: the output contains real secret values.

If `--output` is omitted, the rendered content is written to stdout. You can redirect it yourself:

```bash
skret template nginx.conf.tpl > /etc/nginx/sites-enabled/app.conf
```

## Security: treat output as a secret

The rendered file contains plaintext secret values. Apply the same care you would to a `.env` file:

- **Add the output path to `.gitignore`** — never commit a rendered file.
- **Prefer `--output` over shell redirection** when the file needs restricted permissions.
- **Regenerate at startup** rather than storing the rendered file long-term.

A typical `.gitignore` pattern:

```
*.conf
!*.conf.tpl
```

This ignores rendered `.conf` files while keeping the `.tpl` source templates under version control.
