# Getting Started

Get up and running with skret in under 5 minutes.

## 1. Install

```bash
# macOS
brew install n24q02m/tap/skret

# Windows
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret

# Go
go install github.com/n24q02m/skret/cmd/skret@latest
```

## 2. Initialize

Navigate to your project root and run:

```bash
skret init --provider=aws --path=/myapp/prod --region=us-east-1
```

This creates `.skret.yaml` and updates `.gitignore`.

## 3. Manage Secrets

```bash
# Set a secret
skret set DATABASE_URL "postgres://user:pass@host/db"

# Get it back
skret get DATABASE_URL

# List all secrets
skret list

# Run your app with secrets injected
skret run -- npm start
```

## 4. Multi-Environment

Edit `.skret.yaml` to add environments:

```yaml
version: "1"
default_env: prod

environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1

  dev:
    provider: local
    file: ./.secrets.dev.yaml
```

Switch environments:

```bash
skret --env=dev get DATABASE_URL
skret --env=prod list
```

## 5. Import Existing Secrets

```bash
# From .env file
skret import --from=dotenv --file=.env

# From Doppler
DOPPLER_TOKEN=dp.st.xxx skret import --from=doppler --doppler-project=myapp --doppler-config=prd

# From Infisical
INFISICAL_TOKEN=st.xxx skret import --from=infisical --infisical-project-id=... --infisical-env=prod
```

## Next Steps

- [Configuration Reference](/guide/configuration)
- [Command Reference](/commands/init)
- [AWS Provider Setup](/providers/aws)
