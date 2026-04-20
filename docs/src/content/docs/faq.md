---
title: FAQ
description: "AWS SSM Parameter Store Standard tier:"
---

## Why skret instead of Doppler or Infisical?

**Cost.** Doppler's free tier covers 5 projects. Infisical requires self-hosting for unlimited use, adding operational complexity. If you already use a cloud provider with a native secret manager (AWS SSM, GCP Secret Manager), you are paying for it anyway.

**Simplicity.** skret is a single binary with no server component, no database, no web UI to maintain. Your cloud provider handles encryption, access control, and audit logging.

**Lock-in.** Doppler and Infisical are proprietary platforms. skret wraps standard cloud APIs behind a uniform CLI, so switching from AWS to GCP means changing one line in `.skret.yaml`.

## What does it cost?

AWS SSM Parameter Store Standard tier:

| Resource | Free Tier | Typical Usage (20 repos) |
|----------|-----------|--------------------------|
| Parameters | 10,000 per region | ~200-500 |
| API operations | Unlimited | ~1,000/day |
| KMS decryptions | 20,000/month (AWS-managed key) | ~5,000/month |
| Storage | Included | Included |

**Total: $0/month** for most individual developers and small teams.

Compare:
- Doppler: Free for 5 projects, then $18/user/month
- Infisical: Free (self-hosted), but requires a server (~$10-30/month compute)
- HashiCorp Vault: Free (self-hosted), significant ops overhead

## Does skret work on Windows?

Yes. skret builds for `windows/amd64` and `windows/arm64`. Install via Scoop:

```powershell
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret
```

Platform differences:
- `skret run --` uses a child process (not `syscall.Exec`) on Windows, forwarding the exit code
- File permissions use best-effort ACLs instead of Unix `chmod`
- Shell completions support PowerShell in addition to bash/zsh/fish

## Can I use skret offline?

With the `local` provider, yes. Local secrets are stored in a YAML file on disk:

```yaml
# .skret.yaml
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
```

The `aws` provider requires network access to AWS SSM.

## How do I migrate from Doppler?

```bash
# 1. Initialize skret in your project
skret init --provider=aws --path=/myapp/prod --region=us-east-1

# 2. Import secrets from Doppler
DOPPLER_TOKEN=dp.st.xxx skret import \
  --from=doppler \
  --doppler-project=myapp \
  --doppler-config=prd

# 3. Verify
skret list

# 4. Replace doppler run with skret run in Makefile/CI
# Before: doppler run -- make up-app
# After:  skret run -- make up-app
```

See [Migration from Doppler](/migration/from-doppler) for the full guide.

## How do I migrate from Infisical?

```bash
INFISICAL_TOKEN=st.xxx skret import \
  --from=infisical \
  --infisical-project-id=YOUR_PROJECT_ID \
  --infisical-env=prod

skret list
```

See [Migration from Infisical](/migration/from-infisical) for the full guide.

## Are secrets encrypted?

With the `aws` provider, all secrets are stored as `SecureString` parameters encrypted with KMS. Decryption happens at read time via the AWS SDK. skret never caches decrypted values to disk.

The `local` provider stores secrets in plaintext YAML. It is for development only.

## Does skret store any credentials?

No. skret delegates all authentication to the underlying provider's SDK (AWS SDK credential chain, etc.). Import/sync tokens (`DOPPLER_TOKEN`, `GITHUB_TOKEN`) are read from environment variables, never written to disk.

## Can multiple team members share secrets?

Yes, through your cloud provider's IAM. All team members with the appropriate IAM permissions can read/write secrets at the same SSM path. Access control is managed entirely through IAM policies, not skret.

## What happens if AWS SSM is down?

`skret run --` will fail with exit code 3 (provider error). You can fall back to the local provider for development:

```bash
# Export current secrets for offline use
skret env > .secrets.dev.yaml  # one-time backup

# Switch to local provider
skret --env=dev run -- make start
```

## How do I add a new cloud provider?

See [Adding a Provider](/contributing/adding-provider). Implement the `SecretProvider` interface, register it in the provider registry, add tests (>=95% coverage), and document it.
