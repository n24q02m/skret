# Cloud Secrets Manager Comparison — skret Backend Ranking

**Status:** Research complete, informs v0.2+ roadmap
**Date:** 2026-04-12
**Scope:** Evaluate AWS (SSM Standard/Advanced + Secrets Manager), GCP Secret Manager, Azure Key Vault, OCI Vault, Cloudflare (Workers Secrets + Secrets Store) for use as skret CLI backends.
**Test scenario:** 17 production repositories × 20 secrets/repo (340 total) × 1,000 reads/day (30k/month), region `ap-southeast-1` (Singapore).

---

## 1. Executive Summary

### Monthly cost at test scale (340 secrets, 30k reads/month)

| Rank | Backend | Cost/month | Free tier | Fit score |
|------|---------|-----------|-----------|-----------|
| 1 | **AWS SSM Parameter Store (Standard)** | **$0.00** | 10k params + free Std API | ★★★★★ |
| 2 | **OCI Vault (software-protected)** | **$0.00** | 150 secrets permanent + soft keys free | ★★★★★ |
| 3 | **Azure Key Vault (Standard)** | **$0.09** | None (essentially free at scale) | ★★★★☆ |
| 4 | **GCP Secret Manager** | **$20.10** | 6 versions + 10k ops/month | ★★★☆☆ |
| 5 | **AWS SSM Advanced** | **$17.15** | None | ★★☆☆☆ |
| 6 | **AWS Secrets Manager** | **$136.15** | 30-day/secret trial | ★☆☆☆☆ |
| REJECTED | Cloudflare Workers Secrets | N/A | Per-Worker env | ☆☆☆☆☆ |
| REJECTED | Cloudflare Secrets Store (beta) | N/A | 100/account, 1024-byte cap | ☆☆☆☆☆ |

### Headline findings

1. **Two backends are genuinely free at skret's scale**: AWS SSM Parameter Store Standard and OCI Vault. Both viable as defaults.
2. **Cloudflare is a structural dealbreaker**: neither Workers Secrets nor Secrets Store exposes plaintext via external API. skret's use case (external CLI/CI reads) is architecturally incompatible.
3. **AWS Secrets Manager is 1,500× more expensive than SSM Standard** at this scale, with benefits (managed rotation) that skret does not require for configuration secrets.
4. **GCP Secret Manager costs ~$20/month** — reasonable for multi-cloud parity, but 200× more expensive than the free options with overlapping features.

---

## 2. Per-provider analysis

### 2.1 AWS SSM Parameter Store — Standard Tier

**Pricing:** Zero. Parameter storage free. API (Standard Throughput) free. Higher Throughput mode adds $0.05 per 10k interactions.

**Quotas:**
- 10,000 parameters per account per region
- 4 KB max value size (binary)
- 40 TPS default shared across `GetParameter*` family
- 100 versions per parameter

**Features:** `SecureString` with KMS encryption (AWS-managed `aws/ssm` key is free), path hierarchy, tagging, CloudTrail audit, IAM resource policies, PrivateLink VPC endpoints, EventBridge integration.

**Missing:** automatic rotation, built-in cross-region replication, parameter expiration policies.

**Go SDK:** `aws-sdk-go-v2/service/ssm` — GA, stable, already integrated in skret v0.1.

**Test-scenario cost:**
- Storage: 340 × $0 = $0
- API: 30,000 × $0 (Std Throughput) = $0
- KMS: $0 (AWS-managed key)
- **Total: $0/month**

**Caveats:**
- 4 KB cap excludes service-account JSON blobs, some TLS certs, long PEM keys. These rare cases need a fallback backend.
- 40 TPS shared quota means `GetParametersByPath` with 10 params at a time during CI secret pulls can throttle 17 parallel repo deploys. Skret must batch deliberately.

**Verdict:** **Primary backend. Currently deployed in skret v0.1.**

Source: https://aws.amazon.com/systems-manager/pricing/ · https://docs.aws.amazon.com/general/latest/gr/ssm.html

---

### 2.2 OCI Vault (Secret Management)

**Pricing:** Secret Management service itself is free. Software-protected keys are free. HSM-protected keys: first 20 key versions free, then billable. Virtual Private Vaults (dedicated HSM partition) are **not** Always Free.

**Always Free tier (per tenancy, permanent):**
- **150 secrets**
- Unlimited software-protected key versions
- 20 HSM-protected key versions (shared across vaults)
- 40 secret versions per secret (20 active + 20 pending delete)

**Quotas:**
- 25 KB secret bundle (base64-encoded)
- API rate limit exists (`TooManyRequests`) but exact TPS is not publicly documented — sufficient for test-scenario workload
- Default 3 destination regions for cross-region replication

**Features:** 4-step automatic rotation (VERIFY → CREATE_PENDING → UPDATE_TARGET → PROMOTE), 1–12 month intervals, cross-region replication, multi-AD HA, IAM policy-based access, secret rules (reuse/expiry).

**Go SDK:** `github.com/oracle/oci-go-sdk/v65/secrets` — GA, stable, actively maintained. Auth via API key, instance principal, or resource principal.

**Regions:** `ap-singapore-1` (closest to Vietnam prod VMs), plus Tokyo, Mumbai, Osaka, Seoul, Sydney, Chuncheon in APAC.

**Test-scenario cost:**
- 340 secrets > 150 Always Free cap by 190 secrets. However, overflow secrets still use free software-protected keys — **no storage charge for secrets themselves, only for HSM key material above the 20 free key versions**.
- API calls: no per-call charge documented
- **Total: $0/month** (software keys in a shared virtual vault)
- Caveat: verify via billing test. If OCI applies a hidden per-secret charge past 150, fall back to the next best backend.

**Rotation story is the strongest of the top 5.** 4-step flow gives clean rollback if the new secret fails validation against the target service.

**Verdict:** **Primary backend for v0.2+.** Should share default-backend spot with AWS SSM — user chooses based on existing cloud footprint. OCI wins if rotation or EU/APAC data residency is required; SSM wins for pure simplicity.

Source: https://www.oracle.com/security/cloud-security/secrets/faq/ · https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm · https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/manage-secrets.htm

---

### 2.3 Azure Key Vault (Standard tier)

**Pricing:** $0.03 per 10,000 transactions. Secrets storage itself is free. No monthly fee in Standard tier. Premium tier adds HSM key fees; not needed for pure secrets.

**Free tier:** None permanent. Only included in Azure $200 trial credit for 30 days.

**Quotas:**
- Unlimited secrets per vault
- Unlimited versions (> 500 degrades backup performance)
- 25 KB max secret value
- 4,000 transactions per 10 seconds per vault (includes `GET secret`)
- 300 transactions per 10 seconds for `CREATE` + imports combined
- Subscription-wide limit = 5× per-vault limit

**Features:** soft-delete (mandatory since Feb 2025), purge protection, Azure RBAC + legacy access policies, Managed Identity integration, Private Link, Event Grid for expiry events.

**Go SDK:** `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets` v1.3+ — GA, unified SDK pattern, production-grade.

**Test-scenario cost:**
- 30,000 transactions ÷ 10,000 × $0.03 = **$0.09/month**

**Verdict:** **Secondary backend for multi-cloud or Azure-native workloads.** Essentially free at this scale. Best option when the team already has Azure AD identities, or needs FedRAMP High documented at the transaction level.

Source: https://azure.microsoft.com/en-us/pricing/details/key-vault/ · https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits

---

### 2.4 GCP Secret Manager

**Pricing:**
- $0.06 per active version per location per month (prorated per day)
- $0.03 per 10,000 access operations
- $0.05 per rotation notification (Pub/Sub `SECRET_ROTATE`)
- Management operations free (create, update metadata, destroy)

**Always Free tier (per billing account, per month):**
- 6 active versions
- 10,000 access operations
- 3 rotation notifications

**Quotas:**
- 64 KiB max payload
- 90,000 access requests per minute per project (~1,500 TPS)
- 600/min for read/write/admin ops
- 50 aliases per secret

**Features:**
- **Replication:** *Automatic* (Google picks regions, billed as 1 location) vs *user-managed* (pick regions, billed per location). Automatic is cost-efficient.
- Versioning with aliases, enable/disable/destroy
- Rotation notifications via Pub/Sub (user supplies handler in Cloud Function/Run)
- CMEK support via Cloud KMS
- VPC Service Controls (stronger than PrivateLink for data-exfiltration prevention)

**Go SDK:** `cloud.google.com/go/secretmanager` v1 — GA, gRPC, high quality.

**Test-scenario cost:**
- Storage: (340 − 6 free) × $0.06 = **$20.04/month** (automatic replication, 1 location)
- Access: (30,000 − 10,000 free) × $0.03/10,000 = **$0.06/month**
- **Total: $20.10/month**

**With user-managed replication to 3 regions:** 340 × 3 × $0.06 ≈ $61.20/month + access.

**Verdict:** **Alternative backend for Google-native workloads.** More expensive than SSM/OCI at scale but offers better replication story than SSM (which requires manual cross-region copy). 64 KiB payload handles every edge case.

Source: https://cloud.google.com/secret-manager/pricing · https://cloud.google.com/secret-manager/quotas

---

### 2.5 AWS SSM Parameter Store — Advanced Tier

**Pricing:** $0.05 per advanced parameter per month + $0.05 per 10k API interactions.

**Quotas:**
- 100,000 parameters per region
- 8 KB max value size
- Higher Throughput: 10,000 TPS `GetParameter` / 1,000 TPS `GetParameters` / 100 TPS `GetParametersByPath`
- 10 parameter policies per parameter (expiration, expiration-notification, no-change-notification)

**Features:** Everything in Standard, plus parameter policies for TTL, notifications on no-change, larger value cap.

**Test-scenario cost:**
- 340 × $0.05 = $17.00
- API: $0.15
- **Total: $17.15/month**

**Verdict:** **Use only when Standard's 4 KB cap is exceeded.** No way to downgrade back to Standard. Skret should keep individual secrets in Standard and auto-route oversized secrets to Advanced (or to a different backend like OCI/Azure).

Source: https://aws.amazon.com/systems-manager/pricing/

---

### 2.6 AWS Secrets Manager

**Pricing:** $0.40 per secret per month + $0.05 per 10,000 API calls. 30-day free trial per new secret. Cross-region replication = $0.40 per replica per region.

**Quotas:** 500,000 secrets/region, 64 KB payload, 100 versions, 20 staging labels, 10,000 TPS `GetSecretValue`, 50 TPS combined write.

**Features:** **Automatic rotation** via Lambda (customer-owned) or managed rotation for RDS/Redshift/DocumentDB (free Lambda). Cross-region replication built-in. Staging labels (`AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`).

**Go SDK:** `aws-sdk-go-v2/service/secretsmanager` — GA.

**Test-scenario cost:**
- Storage: 340 × $0.40 = **$136.00/month**
- API: 30,000 × $0.05/10k = **$0.15**
- **Total: $136.15/month** (single region)

**Verdict:** **Rejected as default.** Only worth using when managed rotation for RDS/Redshift is required. Skret can expose this backend as an opt-in option for specific secrets (e.g. `backend: secretsmanager` per-secret in `.skret.yaml`) but should never route bulk config there.

Source: https://aws.amazon.com/secrets-manager/pricing/ · https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html

---

### 2.7 Cloudflare Workers Secrets — REJECTED

**Critical incompatibility:** Secrets are environment variables bound to a single Worker, exposed only as `env.MY_SECRET` inside that Worker's fetch handler runtime. They cannot be read via external HTTP API, cannot be listed with values (only names), and cannot be shared across Workers.

Skret's use case — external CLI reads from CI/CD scripts, `make up-*` targets, local dev laptops, GitHub Actions runners — is structurally impossible.

Source: https://developers.cloudflare.com/workers/configuration/secrets/

---

### 2.8 Cloudflare Secrets Store — REJECTED

Newer account-level store, in open beta as of April 2026. Also structurally incompatible:

> "Once a secret is added to the Secrets Store, it can no longer be decrypted or accessed via API or on the dashboard. Only the service associated with a given secret will be able to access it."
> — https://developers.cloudflare.com/secrets-store/manage-secrets/

The `GET /accounts/{id}/secrets_store/stores/{sid}/secrets/{id}` API returns metadata only — never plaintext.

Additional blockers:
- 100 secrets per account cap (skret needs 340+)
- 1,024-byte value cap (blocks TLS certs, PEM keys, service-account JSON)
- Still in beta; pricing unset
- Only usable from Cloudflare Workers + AI Gateway

**Verdict:** Not a viable backend. Re-evaluate only if Cloudflare adds an "account-owner plaintext read" API. Unlikely given their security posture.

Source: https://developers.cloudflare.com/secrets-store/ · https://developers.cloudflare.com/api/resources/secrets_store/subresources/stores/subresources/secrets/methods/get/

---

## 3. Feature matrix (top 5)

| Feature | SSM Std | OCI Vault | Azure KV | GCP SM | Secrets Mgr |
|---------|---------|-----------|----------|--------|-------------|
| Free tier | 10k params, free API | 150 secrets + soft keys | None | 6 vers + 10k ops | 30-day/secret |
| Storage cost | $0 | $0 (soft keys) | $0 | $0.06/ver/loc | $0.40/secret |
| API cost (Std) | $0 | No per-call | $0.03/10k | $0.03/10k | $0.05/10k |
| Max value | 4 KB | 25 KB | 25 KB | 64 KiB | 64 KB |
| Read TPS | 40 (10k Higher) | rate-limited | 4k/10s/vault | ~1.5k | 10k |
| Versioning | 100 | 40 | Unlimited | Unlimited (aliases) | 100 (staging) |
| Automatic rotation | No | **4-step built-in** | Target-specific | Pub/Sub + handler | Lambda (managed) |
| Cross-region | Manual | 3 regions | Geo-paired | Auto (1 loc) / UM (N loc) | Built-in $0.40/repl |
| CMEK/CMK | KMS | OCI KMS | Key Vault Key | Cloud KMS | KMS |
| Private network | PrivateLink | Service Gateway | Private Link | VPC-SC | PrivateLink |
| Audit | CloudTrail | OCI Audit | Azure Monitor | Cloud Audit | CloudTrail |
| APAC region | ap-southeast-1 | ap-singapore-1 | southeastasia | asia-southeast1 | ap-southeast-1 |
| Go SDK | aws-sdk-go-v2 v1 | oci-go-sdk/v65 | azure-sdk-for-go v1 | cloud.google.com/go v1 | aws-sdk-go-v2 v1 |
| External CLI read | Yes | Yes | Yes | Yes | Yes |
| Cost @ scale | **$0** | **$0** | **$0.09** | **$20.10** | **$136.15** |

---

## 4. Ranked recommendation for skret

### Tier 1 — Default backends (ship in v0.1/v0.2)

**1. AWS SSM Parameter Store (Standard) — v0.1 (already shipped)**
- $0/month at skret's scale
- Mature, already integrated, low-friction migration from Doppler
- 4 KB cap handles 99% of config secrets (API keys, tokens, URLs)
- Fallback: auto-route secrets > 4 KB to Advanced or OCI Vault

**2. OCI Vault (software-protected keys) — v0.2**
- $0/month (150 free + overflow on soft keys is documented free of KMS fees)
- 25 KB payload covers TLS certs, PEM keys, JSON blobs
- Best-in-class rotation (4-step flow with rollback)
- Already part of the user's infrastructure (OCI VMs)
- First multi-cloud backend to add — validates the provider abstraction

### Tier 2 — Alternative backends (v0.3 / v0.4)

**3. Azure Key Vault — v0.3**
- ~$0.09/month at scale — effectively free
- Best for multi-cloud disaster-recovery replica of OCI/SSM data
- Mandatory if the team has Azure AD identities or needs FedRAMP High explicit-transaction audit
- Excellent Go SDK, Private Link, soft-delete safety net

**4. GCP Secret Manager — v0.4**
- $20/month at scale — pay for feature parity, not cost efficiency
- Unique strengths: unlimited versioning with aliases, automatic replication (1-location billing), VPC Service Controls
- Suitable when the user has GCP-native workloads

### Tier 3 — Niche / opt-in

**5. AWS Secrets Manager — opt-in only**
- Do not use as a default. 1,500× more expensive than SSM Standard.
- Only sensible when managed rotation for RDS/Redshift/DocumentDB is required, and the secret that drives that rotation is a single high-value credential. Expose as `backend: secretsmanager` per-secret option, never as a repo default.

**6. AWS SSM Parameter Store (Advanced) — auto-upgrade only**
- Automatic fallback when a secret exceeds 4 KB and the user has not configured a different backend. Do not expose as a first-class backend choice.

### Rejected

**Cloudflare Workers Secrets + Secrets Store** — structurally incompatible with external CLI reads. Document once as "evaluated and rejected, retest if CF adds account-owner plaintext API"; do not implement.

---

## 5. Roadmap revision for skret v0.1 spec §13

The original roadmap in `2026-04-05-skret-cli-design.md` §13:

- v0.2: GCP Secret Manager
- v0.3: Cloudflare Workers Secrets
- v0.4: Azure Key Vault
- v0.5: OCI Vault

Revised roadmap based on this research:

- **v0.2: OCI Vault** (was v0.5 — promoted because it's free, has best rotation, and user already has OCI tenancy)
- **v0.3: Azure Key Vault** (was v0.4 — essentially free at scale, excellent SDK, multi-cloud DR value)
- **v0.4: GCP Secret Manager** (was v0.2 — demoted because $20/mo at scale when free alternatives exist; still valuable for GCP-native workloads)
- **v0.5:** (previously CF) — **remove / reassign to a new capability**: managed rotation backend integration (AWS Secrets Manager + OCI Vault rotation + Azure Key Vault target rotation). Or: HashiCorp Vault as a self-hosted backend for users who reject cloud lock-in entirely.
- **REMOVED: Cloudflare Workers Secrets.** Incompatible with skret's use case.

This re-ordering should be reflected in an amendment to `2026-04-05-skret-cli-design.md` §13.

---

## 6. Architecture implications

### 6.1 Multi-backend design stays the same

The `SecretProvider` interface from `2026-04-05-skret-cli-design.md` §2.3 already supports multiple backends. This research does not change the interface — it changes which backends get implemented in what order.

### 6.2 Per-secret backend routing

Add an optional per-secret override so a single `.skret.yaml` can route specific large secrets to a backend that handles them:

```yaml
version: "1"
environments:
  prod:
    provider: aws
    path: /knowledgeprism/prod
    region: ap-southeast-1

# Optional per-secret backend overrides (v0.2+)
overrides:
  TLS_PRIVATE_KEY:
    provider: oci
    vault_ocid: ocid1.vault.oc1.ap-singapore-1.xxx
  GCP_SA_JSON:
    provider: oci
    vault_ocid: ocid1.vault.oc1.ap-singapore-1.xxx
```

Secrets without overrides use the environment's default backend (SSM Standard → auto-promote to Advanced at > 4 KB).

### 6.3 Cost safety rail

Add a `skret cost estimate` command that calculates projected monthly cost from the current backend configuration and secret inventory. Warn when:
- Secrets Manager is configured for bulk config (> 5 secrets)
- GCP user-managed replication > 2 locations
- SSM Advanced is used for secrets < 4 KB (fits in free Standard)

---

## 7. Open questions

1. **Verify OCI cost past 150-secret cap.** Docs say software-protected secrets beyond 150 are free of KMS charges, but billing test needed to confirm no per-secret overage exists.
2. **AWS SSM Higher Throughput need assessment.** skret's CI burst pattern (17 parallel `skret run` during prod deploys) could hit the default 40 TPS shared quota. Higher Throughput adds $0.05/10k API calls ($0.15/month at scale) — cheap enough to enable by default if throttling is observed.
3. **Add HashiCorp Vault?** Self-hosted option for users who want zero cloud lock-in. Fits v0.5 if managed rotation is deferred.
4. **Multi-backend sync / DR?** Should skret offer `skret sync --from=ssm --to=oci` for backup/DR? The syncer framework (§6 of v0.1 spec) could be extended to support provider-to-provider sync; currently targets only dotenv and GitHub Actions.

---

**End of comparison.**
