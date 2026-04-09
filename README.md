# skret

[![CI](https://github.com/n24q02m/skret/actions/workflows/ci.yml/badge.svg)](https://github.com/n24q02m/skret/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/n24q02m/skret)](https://goreportcard.com/report/github.com/n24q02m/skret)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cloud-provider secret manager CLI wrapper with Doppler/Infisical-grade developer experience. Zero Lock-in. Zero Server.

> **skret** wraps native cloud secret managers (AWS SSM Parameter Store, GCP Secret Manager, etc.) with a unified, ergonomic CLI. It gives your team the DX of Doppler or Infisical, but relies entirely on your own AWS infrastructure for security and storage (BYOC).

## Key Capabilities (Why replace Doppler/Infisical?)

*   **Zero-Server (Decentralized):** No third-party database holds your secrets. Data never leaves your AWS account.
*   **Automatic Cross-Reference Expansion:** Define secrets that inherit from each other (e.g., `DB_URL=postgres://${DB_USER}:${DB_PASS}@host`). Skret automatically recursively resolves these relationships when injecting into your app.
*   **Built-in History & Rollback:** Native support for viewing secret versions and seamlessly rolling back directly via AWS SSM's versioning backend.
*   **Cross-Environment:** `dev`, `staging`, `prod` configurations synced to paths in the cloud, defined cleanly in `.skret.yaml`.

## Installation

### macOS (Homebrew)

```bash
brew install n24q02m/tap/skret
```

### Binary Download

Download directly from [GitHub Releases](https://github.com/n24q02m/skret/releases).

---

## 🚀 The "Zero-Setup" Developer Workflow

If your AWS account is already configured (or if you are an Admin), `skret` requires **zero manual IAM setup**.

**1. Login to AWS (Only once):**
```bash
aws sso login
```

**2. Initialize `skret` safely in your project:**
```bash
skret init --provider=aws --path=/myapp/prod --region=us-east-1
```

**3. Set Cross-Reference Secrets:**
```bash
skret set DB_USER admin
skret set DB_PASS super_secret
skret set DB_URL 'postgres://${DB_USER}:${DB_PASS}@localhost:5432/mydb'
```

**4. Run Your App (Automatic Injection!):**
```bash
skret run -- node index.js
```
*(Your Node.js app will read `DB_URL` fully resolved to `postgres://admin:super_secret@localhost:5432/mydb`)*

**5. Rollback Mistakes Instantly:**
```bash
skret history DB_URL
skret rollback DB_URL --version 1
```

---

## 🔒 DevOps & Administrator Setup

Unlike Doppler, you do not need to manually invite developers or issue static personal access tokens. Skret uses your native AWS IAM.

To give a developer access, simply assign them an IAM Policy limiting explicitly what path they can read/write:

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ssm:PutParameter",
            "ssm:DeleteParameter",
            "ssm:GetParameterHistory",
            "ssm:GetParametersByPath",
            "ssm:GetParameters",
            "ssm:GetParameter"
        ],
        "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/dev/*"
    }]
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) © n24q02m
