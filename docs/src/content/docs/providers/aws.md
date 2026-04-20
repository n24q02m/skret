---
title: AWS SSM Parameter Store
description: "Minimum required permissions:"
---

## Setup

### Prerequisites

- AWS account with SSM Parameter Store access
- AWS credentials configured (env vars, `~/.aws/credentials`, IAM roles, or SSO)

### IAM Policy

Minimum required permissions:

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
        "ssm:DeleteParameter"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/myapp/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt"],
      "Resource": "arn:aws:kms:*:*:key/*"
    }
  ]
}
```

### Configuration

```yaml
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
    profile: production    # Uses named profile from ~/.aws/credentials
    kms_key_id: arn:aws:kms:us-east-1:123456789:key/abc-def  # Optional
```

## Usage

```bash
# Set a secret (stored as SecureString)
skret set /myapp/prod/DATABASE_URL "postgres://prod-host/db"

# Get a secret (auto-decrypts)
skret get /myapp/prod/DATABASE_URL

# List all secrets under path
skret list

# Run with injected env vars (path prefix stripped)
skret run -- node server.js
# DATABASE_URL=postgres://prod-host/db is injected
```

## Quotas

| Resource | Limit |
|----------|-------|
| Parameter value size | 4 KB (standard), 8 KB (advanced) |
| Parameters per account/region | 10,000 (standard) |
| GetParametersByPath throughput | 40 TPS |

## Security

- All parameter values are stored as `SecureString` (encrypted with KMS)
- Decryption happens at read time, never cached to disk
- IAM policies control access per path prefix
