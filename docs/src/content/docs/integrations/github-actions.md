---
title: GitHub Actions
description: "Use Skret in GitHub Actions with short-lived, read-only AWS OIDC credentials."
---

Use Skret in a consumer workflow with a repository-scoped AWS OIDC role. The workflow may read its approved SSM namespace to launch a process; it must not project or rotate secrets into GitHub or another provider.

## OIDC Setup

### 1. Create the IAM OIDC Provider

Create the GitHub Actions OIDC provider once per AWS account, following the current AWS and GitHub guidance for `https://token.actions.githubusercontent.com` with audience `sts.amazonaws.com`.

### 2. Create the IAM Role

Limit the trust policy to the intended repository and, where possible, its protected branch or environment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### 3. Attach a Read-only SSM Policy

Scope both SSM and KMS access to the namespace and key used by this repository:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/KEY-ID",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "ssm.us-east-1.amazonaws.com"
        }
      }
    }
  ]
}
```

Do not add `PutParameter`, label mutation, GitHub secret-write, Cloudflare write, or deployment permissions to this consumer role.

## Run Tests with Secrets

The example pins every third-party action to an immutable commit. The one-shot installer requires and uses `cosign`, verifies the release checksum/signature, enforces `SAFE-ARCHIVE-V1`, and smokes the installed binary before success.

```yaml
name: CI
on: [push, pull_request]

permissions:
  id-token: write
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803

      - name: Configure read-only AWS credentials
        uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c
        with:
          role-to-assume: arn:aws:iam::123456789012:role/skret-github-actions
          aws-region: us-east-1
          allowed-account-ids: "123456789012"

      - name: Install cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6

      - name: Install verified Skret release
        run: |
          curl -fsSL https://skret.n24q02m.com/install.sh | sh -s -- --user --no-completion
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Run tests with secrets
        run: skret run -- go test ./...
```

Keep untrusted pull requests away from the OIDC-bearing job. Use a protected branch/environment and GitHub's permission controls for any workflow that can request the role.

## Projection and Rotation

Do not run `skret sync`, `skret delete`, or provider-setting mutation from an ordinary GitHub Actions workflow. In the hosted architecture:

1. the credential-free planner accepts bounded, signed, value-free planning input;
2. the separate security executor verifies the exact operation and target allowlist;
3. provider credentials and KMS access remain executor-only;
4. ambiguous write responses retain the source envelope and require reconciliation rather than an automatic retry.

An operator may still run an explicit local `skret sync` or `skret sync --rotate` from a trusted environment with the documented target credentials. That is a manual operator boundary, not a reusable CI projection job.

## Security Considerations

- Restrict OIDC trust to the exact repository and protected ref or environment.
- Use read-only SSM/KMS permissions for consumer workflows.
- Pin every action to a full commit SHA and review automated pin updates.
- Install Skret through a checksum/signature-verifying path; do not stream an unverified archive directly into `tar`.
- OIDC credentials are short-lived, but their permissions still determine impact. A short TTL does not make provider-write scope acceptable in ordinary CI.
- Do not print `skret env`, process environments, provider responses, or secret values in workflow logs.
