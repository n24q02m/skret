# Provider Comparison & Ranking

skret supports multiple cloud-provider secret backends. This page ranks them by cost, features, and fit for typical skret use cases.

## TL;DR

| Rank | Backend | Monthly cost* | Recommended for |
|------|---------|---------------|-----------------|
| 1 | **AWS SSM Parameter Store (Standard)** | **$0** | Default for most users — AWS-native or mixed-cloud |
| 2 | **OCI Vault (software-protected)** | **$0** | Best rotation; users with OCI tenancy |
| 3 | **Azure Key Vault (Standard)** | **~$0.09** | Azure-native workloads, multi-cloud DR |
| 4 | **GCP Secret Manager** | **~$20** | GCP-native workloads, large (>25 KB) payloads |
| 5 | **AWS Secrets Manager** | **~$136** | Only when managed rotation (RDS/Redshift) is required |
| — | Cloudflare Workers Secrets | — | **Not supported** — plaintext not readable externally |
| — | Cloudflare Secrets Store | — | **Not supported** — plaintext not readable externally |

\* *Cost based on reference scenario: 17 repos × 20 secrets/repo × 1,000 reads/day (30k/month), `ap-southeast-1`/Singapore region.*

## Choosing a backend

Use this decision tree:

```
Are your secrets > 4 KB (TLS certs, PEM keys, JSON blobs)?
├── No → AWS SSM Parameter Store (Standard)           [rank 1, $0]
└── Yes
    ├── Do you have OCI infrastructure already?
    │    └── Yes → OCI Vault                           [rank 2, $0]
    ├── Do you run on Azure / need Azure AD identity?
    │    └── Yes → Azure Key Vault                     [rank 3, ~$0.09]
    ├── Do you run on GCP?
    │    └── Yes → GCP Secret Manager                  [rank 4, ~$20]
    └── Do you need automatic rotation for RDS/Redshift?
         └── Yes → AWS Secrets Manager (opt-in, per-secret)
```

You can mix backends in a single `.skret.yaml`: default environment uses SSM, specific oversized secrets route to OCI Vault via the `overrides:` block (v0.4+).

## Cost at different scales

### Solo developer (1 repo × 20 secrets × 100 reads/day)

| Backend | Monthly cost |
|---------|-------------|
| AWS SSM Standard | $0 |
| OCI Vault | $0 (within 150 free cap) |
| Azure Key Vault | ~$0.01 |
| GCP Secret Manager | ~$0.84 (14 active versions × $0.06) |
| AWS Secrets Manager | ~$8.00 |

### Small team (5 repos × 30 secrets × 5,000 reads/day)

| Backend | Monthly cost |
|---------|-------------|
| AWS SSM Standard | $0 |
| OCI Vault | $0 (150 free cap applies) |
| Azure Key Vault | ~$0.45 |
| GCP Secret Manager | ~$9 |
| AWS Secrets Manager | ~$60 |

### skret reference scale (17 repos × 20 secrets × 1,000 reads/day)

| Backend | Monthly cost |
|---------|-------------|
| AWS SSM Standard | $0 |
| OCI Vault | $0 (overflow uses free software keys) |
| Azure Key Vault | ~$0.09 |
| GCP Secret Manager | ~$20.10 |
| AWS Secrets Manager | ~$136.15 |

### Large scale (100 repos × 50 secrets × 100,000 reads/day)

| Backend | Monthly cost |
|---------|-------------|
| AWS SSM Standard | $0 to ~$1.50 (may need Higher Throughput) |
| OCI Vault | $0 (software keys; verify billing) |
| Azure Key Vault | ~$0.90 |
| GCP Secret Manager | ~$300 |
| AWS Secrets Manager | ~$2,000 |

## Feature matrix

See [../superpowers/specs/2026-04-12-secrets-provider-comparison.md](../superpowers/specs/2026-04-12-secrets-provider-comparison.md) for the full matrix including:

- Free tier details per provider
- Max secret value sizes (4 KB – 64 KB)
- API rate limits (40 – 90,000 req/min)
- Versioning semantics (fixed 100 vs unlimited with aliases)
- Automatic rotation support (none / Lambda / 4-step / Pub/Sub)
- Cross-region replication modes
- Audit logging integrations
- Private-network options (PrivateLink / Service Gateway / VPC-SC)
- Go SDK maturity per provider
- Compliance certifications (SOC 2, ISO 27001, FedRAMP High, HIPAA, PCI-DSS)
- APAC region coverage

## Why Cloudflare is not supported

Both Cloudflare Workers Secrets and Cloudflare Secrets Store are architecturally incompatible with skret:

- **Workers Secrets** are scoped to a single Worker, only accessible as `env.MY_SECRET` inside that Worker's fetch handler. No external API returns plaintext.
- **Secrets Store** (beta) is explicit: *"Once a secret is added to the Secrets Store, it can no longer be decrypted or accessed via API or on the dashboard. Only the service associated with a given secret will be able to access it."* The `GET` API returns metadata only.

skret's core use case is external CLI reads from CI/CD pipelines, `make up-*` targets, local development laptops, and GitHub Actions runners. Cloudflare's design intentionally prevents this. This is not a gap skret can paper over.

If Cloudflare ever adds an account-owner plaintext read API, skret will re-evaluate. Track: [Cloudflare Secrets Store roadmap](https://developers.cloudflare.com/secrets-store/).

## When a backend crosses a tier threshold

skret warns in `skret cost estimate` output (v0.5+) when a configuration is needlessly expensive:

- A repo default set to AWS Secrets Manager for bulk config → suggests SSM Standard.
- GCP user-managed replication across 3+ locations when automatic replication (1-location billing) would serve the same purpose.
- SSM Advanced used for secrets that fit in 4 KB → recommends Standard.

This is advisory; skret does not change provider selection automatically.
