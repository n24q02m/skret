---
title: Cloud Secrets Manager Comparison
description: "Public reference for skret's supported and roadmap backends. Numbers below use a representative scale: 340 secrets, 30k reads/month, `ap-southeast-1` (Singapore"
---

Public reference for skret's supported and roadmap backends. Numbers below use a representative scale: 340 secrets, 30k reads/month, `ap-southeast-1` (Singapore) region.

## Monthly cost at reference scale

| Rank | Backend | Cost/month | Free tier | Fit |
|------|---------|-----------|-----------|-----|
| 1 | **AWS SSM Parameter Store (Standard)** | **$0.00** | 10k params + free Std API | Primary |
| 2 | **OCI Vault (software-protected)** | **$0.00** | 150 secrets permanent | Tier-1 roadmap |
| 3 | **Azure Key Vault (Standard)** | **$0.09** | None (effectively free at scale) | Tier-1 roadmap |
| 4 | **GCP Secret Manager** | **$20.10** | 6 versions + 10k ops/month | Tier-2 roadmap |
| 5 | **AWS SSM Advanced** | **$17.15** | None | Fallback for >4 KB |
| 6 | **AWS Secrets Manager** | **$136.15** | 30-day/secret trial | Only for managed rotation |

## Headline findings

1. **Two backends are genuinely free at this scale**: AWS SSM Parameter Store (Standard) and OCI Vault (software-protected). Both viable as defaults.
2. **AWS Secrets Manager is ~1,500× more expensive than SSM Standard** at this scale, with benefits (managed rotation) that most configuration secrets do not require.
3. **GCP Secret Manager costs ~$20/month** — reasonable for multi-cloud parity, but 200× more expensive than the free options with overlapping features.

## Feature matrix

| Feature | AWS SSM Std | OCI Vault | Azure KV Std | GCP SM | AWS Secrets Mgr |
|---------|-------------|-----------|--------------|--------|-----------------|
| Max value size | 4 KB | 25 KB | 25 KB | 64 KB | 64 KB |
| Versioning | 100 fixed | 40 / secret | unlimited | unlimited + aliases | unlimited |
| Automatic rotation | — | 4-step lifecycle | via Event Grid | Pub/Sub triggers | Lambda (managed) |
| Cross-region replication | Manual | Manual | Geo-redundant (premium) | Auto / user-managed | Auto replica |
| Audit log | CloudTrail | OCI Audit | Azure Monitor | Cloud Audit | CloudTrail |
| Private network | PrivateLink | Service Gateway | Private Endpoint | VPC-SC | PrivateLink |
| KMS integration | `aws/ssm` free | Software/HSM keys | Managed HSM | CMEK | `aws/secretsmanager` |
| IAM model | IAM policies | IAM + compartments | RBAC + Azure AD | IAM + conditions | IAM policies |
| API rate limit | 40 TPS shared | Soft-limited | 2k req/10s | 90k read/min | 10k TPS |
| Go SDK maturity | GA (v2) | GA | GA (track-2) | GA | GA (v2) |

### Compliance certifications

| Backend | SOC 2 | ISO 27001 | FedRAMP High | HIPAA | PCI-DSS |
|---------|-------|-----------|--------------|-------|---------|
| AWS SSM | ✓ | ✓ | ✓ | ✓ | ✓ |
| OCI Vault | ✓ | ✓ | ✓ | ✓ | ✓ |
| Azure Key Vault | ✓ | ✓ | ✓ | ✓ | ✓ |
| GCP Secret Manager | ✓ | ✓ | ✓ | ✓ | ✓ |
| AWS Secrets Manager | ✓ | ✓ | ✓ | ✓ | ✓ |

### APAC region coverage

| Backend | Singapore | Tokyo | Seoul | Mumbai | Sydney |
|---------|-----------|-------|-------|--------|--------|
| AWS SSM | ap-southeast-1 | ap-northeast-1 | ap-northeast-2 | ap-south-1 | ap-southeast-2 |
| OCI Vault | ap-singapore-1 | ap-tokyo-1 | ap-seoul-1 | ap-mumbai-1 | ap-sydney-1 |
| Azure KV | southeastasia | japaneast | koreacentral | centralindia | australiaeast |
| GCP SM | asia-southeast1 | asia-northeast1 | asia-northeast3 | asia-south1 | australia-southeast1 |
| AWS Secrets Manager | ap-southeast-1 | ap-northeast-1 | ap-northeast-2 | ap-south-1 | ap-southeast-2 |

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
| OCI Vault | $0 (within 150 free cap) |
| Azure Key Vault | ~$0.45 |
| GCP Secret Manager | ~$9 |
| AWS Secrets Manager | ~$60 |

### Large scale (100 repos × 50 secrets × 100,000 reads/day)

| Backend | Monthly cost |
|---------|-------------|
| AWS SSM Standard | $0 to ~$1.50 (may need Higher Throughput) |
| OCI Vault | $0 (software keys; verify billing) |
| Azure Key Vault | ~$0.90 |
| GCP Secret Manager | ~$300 |
| AWS Secrets Manager | ~$2,000 |

## Recommended default

**AWS SSM Parameter Store (Standard)** is skret's default:

- $0/month at any realistic scale under 10k parameters.
- `SecureString` with AWS-managed KMS key is free.
- CloudTrail audit is included.
- 4 KB limit covers the vast majority of configuration secrets. The rare oversized items (TLS certs, JSON blobs) can use a secondary backend via `overrides:` in `.skret.yaml`.

Users with existing OCI tenancy can set **OCI Vault (software-protected)** as default with equivalent cost. Tier-2 and Tier-3 backends come online as skret's provider registry expands.

## Sources

- AWS SSM pricing: <https://aws.amazon.com/systems-manager/pricing/>
- AWS Secrets Manager pricing: <https://aws.amazon.com/secrets-manager/pricing/>
- OCI Vault pricing: <https://www.oracle.com/security/cloud-security/key-management/>
- Azure Key Vault pricing: <https://azure.microsoft.com/pricing/details/key-vault/>
- GCP Secret Manager pricing: <https://cloud.google.com/secret-manager/pricing>
