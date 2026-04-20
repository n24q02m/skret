---
title: GitHub Actions
description: "Use skret in GitHub Actions with OIDC for secure, credential-free access to AWS SSM."
---

Use skret in GitHub Actions with OIDC for secure, credential-free access to AWS SSM.

## OIDC Setup

### 1. Create the IAM OIDC Provider

Run once per AWS account:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create the IAM Role

Create a trust policy that limits access to your repository:

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
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
        }
      }
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name skret-github-actions \
  --assume-role-policy-document file://trust-policy.json
```

### 3. Attach SSM Read Policy

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
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "ssm.us-east-1.amazonaws.com"
        }
      }
    }
  ]
}
```

```bash
aws iam put-role-policy \
  --role-name skret-github-actions \
  --policy-name ssm-read \
  --policy-document file://ssm-policy.json
```

## Workflow Examples

### Basic: Run tests with secrets

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

      - name: Run tests with secrets
        run: skret run -- go test ./...
```

### Sync secrets to GitHub Actions

Push secrets from AWS SSM to GitHub Actions repository secrets:

```yaml
name: Sync Secrets
on:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

permissions:
  id-token: write
  contents: read

jobs:
  sync:
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

      - name: Sync to GitHub Actions
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          skret sync --to=github \
            --github-repo=${{ github.repository }} \
            --from-env=prod
```

### Multi-repo sync

```yaml
      - name: Sync to multiple repos
        env:
          GITHUB_TOKEN: ${{ secrets.GH_PAT }}  # PAT with repo scope
        run: |
          skret sync --to=github \
            --github-repo=your-org/app-frontend,your-org/app-backend \
            --from-env=prod
```

## Security Considerations

- **Restrict the trust policy** to specific branches if needed: `repo:org/repo:ref:refs/heads/main`
- **Use least-privilege IAM** -- read-only for CI, read-write only for sync jobs
- The `id-token: write` permission is required for OIDC. Without it, the `configure-aws-credentials` action cannot request a token.
- OIDC tokens are short-lived (valid for the duration of the workflow run)
