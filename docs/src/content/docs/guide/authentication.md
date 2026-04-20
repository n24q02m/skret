---
title: Authentication
description: "skret delegates all authentication to the underlying provider's SDK. It stores no credentials itself."
---

skret delegates all authentication to the underlying provider's SDK. It stores no credentials itself.

## AWS Credential Chain

The AWS provider uses the [AWS SDK v2 default credential chain](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-sdk.html), resolved in this order:

1. **Environment variables** -- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Shared credentials file** -- `~/.aws/credentials` with named profiles
3. **Shared config file** -- `~/.aws/config` (SSO profiles, process credentials)
4. **ECS container credentials** -- `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
5. **EC2 IMDS** -- Instance Metadata Service (when running on EC2/ECS)
6. **IAM Roles Anywhere** -- X.509 certificate-based auth

### Environment Variables

Simplest method. Set directly or inject via CI:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-east-1

skret list
```

### Named Profiles

Configure profiles in `~/.aws/credentials`:

```ini
[production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Reference in `.skret.yaml`:

```yaml
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
    profile: production
```

Or override via CLI/env var:

```bash
skret --profile=production list
AWS_PROFILE=production skret list
```

### AWS SSO

Configure SSO in `~/.aws/config`:

```ini
[profile my-sso]
sso_start_url = https://my-org.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = ReadOnlyAccess
region = us-east-1
```

Login first, then use skret:

```bash
aws sso login --profile my-sso
skret --profile=my-sso list
```

### EC2/ECS Instance Roles

No configuration needed. The SDK automatically uses IMDS credentials when running on AWS infrastructure:

```yaml
# .skret.yaml on an EC2 instance
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
    # No profile needed -- uses instance role
```

### OIDC for GitHub Actions

Use GitHub's OIDC provider to assume an IAM role without long-lived credentials. See the [GitHub Actions integration](/integrations/github-actions) for the full setup.

## IAM Policy Examples

### Read-only (CI/CD, deployments)

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
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/prod/*"
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

### Read-write (secret management)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "ssm:DeleteParameter",
        "ssm:AddTagsToResource",
        "ssm:ListTagsForResource"
      ],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
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

### Scoped per environment

Restrict IAM users/roles to specific environments:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProdReadOnly",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParametersByPath"],
      "Resource": "arn:aws:ssm:*:*:parameter/myapp/prod/*"
    },
    {
      "Sid": "StagingFullAccess",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParametersByPath", "ssm:PutParameter", "ssm:DeleteParameter"],
      "Resource": "arn:aws:ssm:*:*:parameter/myapp/staging/*"
    }
  ]
}
```

## Precedence

Authentication-related settings follow the same precedence as all config:

1. CLI flags (`--profile`, `--region`)
2. Environment variables (`SKRET_PROFILE`, `SKRET_REGION`, `AWS_PROFILE`, `AWS_REGION`)
3. `.skret.yaml` environment config
4. AWS SDK defaults

## Import/Sync Authentication

Importers and syncers use their own credentials:

| Source/Target | Credential | Environment Variable |
|---|---|---|
| Doppler | Service token | `DOPPLER_TOKEN` |
| Infisical | Machine identity or bearer token | `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET` or `INFISICAL_TOKEN` |
| GitHub Actions | PAT with `repo` scope | `GITHUB_TOKEN` |
