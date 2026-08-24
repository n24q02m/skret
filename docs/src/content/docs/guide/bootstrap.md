---
title: Bootstrap
description: "One command to provision a scoped, permanent skret key from an admin identity."
---

Provision a dedicated, least-privilege skret identity in one command. From an
admin or root identity, `skret bootstrap` creates a scoped IAM user with a
permanent access key, stores the key locally, and never persists the admin
credential.

```bash
skret bootstrap
```

It resolves the SSM path, region, and profile from your `.skret.yaml` (the same
way other commands do), or you can pass them explicitly. The admin credential is
read once from the AWS chain (or `--profile`) to call IAM and STS; only the new
scoped key is saved.

## What it creates

For path `/myapp/prod` and project `myapp`, bootstrap creates:

- **An IAM user** named `skret-<project>` (e.g. `skret-myapp`). If the user
  already exists it is reused — bootstrap is idempotent.
- **A permanent access key** for that user, stored in `~/.skret/credentials.yaml`.
  There is no expiry.
- **An inline least-privilege policy** (also named `skret-<project>`) granting
  exactly the SSM actions skret uses, scoped to `parameter/<path>/*`, plus the
  KMS actions constrained to SSM via `kms:ViaService`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SkretSSM",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:GetParameterHistory",
        "ssm:PutParameter",
        "ssm:DeleteParameter"
      ],
      "Resource": "arn:aws:ssm:<region>:<account>:parameter/<path>/*"
    },
    {
      "Sid": "SkretKMSViaSSM",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "kms:ViaService": "ssm.<region>.amazonaws.com" }
      }
    }
  ]
}
```

## How it works

Bootstrap runs these steps:

1. **Verify identity** — calls STS `GetCallerIdentity` with the admin credential
   to confirm who you are and resolve the account ID.
2. **Create the IAM user** `skret-<project>` (reused if it already exists).
3. **Attach the inline policy** scoped to your SSM path.
4. **Create an access key** for the user.
5. **Store it** in the local credential cache without writing secret material to stdout or stderr.

The admin or root credential is used only for these calls and is **never stored**. The generated scoped key remains inside the credential cache used by the current machine.

## Another machine or team member

`skret bootstrap` is deliberately local: it always stores the generated scoped credential for the current machine and never prints a secret access key. The former `--print-only` handoff path was removed because terminal output, scrollback, shell capture, and CI logs are not credential transports.

Prefer IAM Identity Center SSO for another machine or team member:

```bash
skret auth login aws --method sso
```

If a separate static IAM identity is required, run bootstrap on that destination with a temporary, approved admin profile, verify the scoped credential was stored, then remove the temporary admin access. Alternatively, provision and transfer the credential through an organization-approved secret-delivery mechanism outside Skret, then run:

```bash
skret auth login aws --method access-key
```

Never pass a secret access key as a command-line argument or copy it through bootstrap stdout/stderr. See the [authentication guide](/guide/authentication/) for the supported login flows.

## Options

### `--project`

Project name; sets the IAM user/policy name to `skret-<project>` and the default
scope. Defaults to the last segment of the SSM path.

```bash
skret bootstrap --project myapp
```

### `--path`

SSM path to scope the policy to. Defaults to the env path from `.skret.yaml`.

```bash
skret bootstrap --path /myapp/prod
```

### `--region`

AWS region. Defaults to the config/env value.

```bash
skret bootstrap --region ap-southeast-1
```

### `--user-name`

Override the IAM user name (default `skret-<project>`).

```bash
skret bootstrap --user-name skret-ci
```

### `--profile`

AWS profile to use as the bootstrap (admin) identity.

```bash
skret bootstrap --profile admin
```


### `--force`

Provision a new key even if an aws credential is already stored. Without it,
bootstrap is a no-op when a stored credential exists.

```bash
skret bootstrap --force
```

### `--yes`

Skip the confirmation prompt. Required in non-interactive shells — without it,
bootstrap exits `8` before any AWS call.

```bash
skret bootstrap --yes
```

## Security

- The admin or root credential is used once and **never stored** — only the new
  scoped key is saved.
- The generated policy is **least-privilege**: the exact SSM actions skret uses,
  scoped to `parameter/<path>/*`, with KMS constrained to SSM.
- The access key is **permanent**. Prefer running bootstrap from a dedicated
  admin IAM user rather than the account root, and rotate the generated key
  periodically by re-running with `--force`.
- Secret access-key material is never written to bootstrap stdout or stderr. A storage failure reports revocation guidance without echoing the generated credential.
