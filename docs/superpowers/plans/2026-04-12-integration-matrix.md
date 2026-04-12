# skret Integration Matrix — 17 Production Repos

**Created:** 2026-04-12
**Status:** Phase A dry-run pending (requires `aws sso login`)

## Migration source

| Repo | Current manager | Source type | Project/Config |
|------|----------------|-------------|----------------|
| knowledge-core | Infisical | infisical | self-hosted |
| wet-mcp | Doppler | doppler | wet-mcp/prd |
| better-code-review-graph | Doppler | doppler | better-crg/prd |
| mnemo-mcp | Doppler | doppler | mnemo-mcp/prd |
| mcp-relay-core | Doppler | doppler | mcp-relay/prd |
| better-notion-mcp | Doppler | doppler | better-notion/prd |
| better-email-mcp | Doppler | doppler | better-email/prd |
| better-telegram-mcp | Doppler | doppler | better-tg/prd |
| better-godot-mcp | Doppler | doppler | better-godot/prd |
| LinguaSense | Infisical | infisical | self-hosted |
| oci-vm-infra | Doppler | doppler | oci-infra/prd |
| oci-vm-prod | Doppler | doppler | oci-prod/prd |
| web-core | Doppler | doppler | web-core/prd |
| virtual-company | Doppler | doppler | virtual-co/prd |
| QuikShipping | Doppler | doppler | quikship/prd |
| Aiora | Infisical | infisical | self-hosted |
| KnowledgePrism | Infisical | infisical | self-hosted |

## Target SSM path convention

`/<repo-slug>/<env>/<KEY_NAME>` in region `ap-southeast-1`

## Phase A — Dry-run results

| # | Repo | skret init | import --dry-run | Keys found | Decision |
|---|------|-----------|-----------------|------------|----------|
| 1 | knowledge-core | | | | |
| 2 | wet-mcp | | | | |
| 3 | better-code-review-graph | | | | |
| 4 | mnemo-mcp | | | | |
| 5 | mcp-relay-core | | | | |
| 6 | better-notion-mcp | | | | |
| 7 | better-email-mcp | | | | |
| 8 | better-telegram-mcp | | | | |
| 9 | better-godot-mcp | | | | |
| 10 | LinguaSense | | | | |
| 11 | oci-vm-infra | | | | |
| 12 | oci-vm-prod | | | | |
| 13 | web-core | | | | |
| 14 | virtual-company | | | | |
| 15 | QuikShipping | | | | |
| 16 | Aiora | | | | |
| 17 | KnowledgePrism | | | | |

## Phase B — Staging results

| # | Repo | SSM imported | Makefile PR | Staging health | 48h observe | Result |
|---|------|-------------|-------------|---------------|-------------|--------|
| 1-17 | (same order) | | | | | |

## Phase C — Production cutover

| # | Repo | Prod PR | CD triggered | 24h health | Result |
|---|------|---------|-------------|------------|--------|
| 1-17 | (same order) | | | | |
