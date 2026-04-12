# skret v0.1 — Hardening & Production Readiness Spec

**Status:** Draft for review
**Date:** 2026-04-11
**Author:** n24q02m
**Supersedes (partially):** `2026-04-05-skret-cli-design.md` (v0.1 design) — this document does NOT replace the original spec; it extends it with an implementation review, template-compliance requirements, PR triage strategy, and integration-testing plan for production adoption.

---

## 1. Purpose

After the v0.1 implementation burst (2026-04-08 → 2026-04-09) and the subsequent Jules/Sentinel/Bolt automated review run (2026-04-09 → 2026-04-10), skret reached a state that is functionally close to the v0.1 spec but has:

- 27 unmerged pull requests (Jules refactor / Sentinel security / Bolt perf / Renovate / Palette) in open review limbo.
- Template compliance gaps against the 18 production repositories (`github.com/stars/n24q02m/lists/productions`), particularly a missing CodeRabbit configuration, missing GitHub issue/PR templates, an underdeveloped `.github/best_practices.md`, and a weaker branch ruleset than the ecosystem standard.
- Unintended scope creep (the `history` and `rollback` commands landed on `main` even though the v0.1 design document places them in v0.5).
- Root-level artifacts that should never have been committed (`skret.exe` binary, ad-hoc `patch.py` and `patch_aws_interface.ps1` scripts).
- An empty `CHANGELOG.md` because `python-semantic-release` has never been executed.
- A coverage rate of **79.5 %** across `internal/` (with `internal/provider/aws` at 65.2 %) while the original spec requires ≥ 95 % on `internal/` and ≥ 90 % on `pkg/`.
- `pkg/skret/` with zero test files.
- A docs site covering only a fraction of the sections enumerated in spec §11.2.
- Zero real-world validation against any of the 17 consumer production repositories — skret has never been plugged into `KnowledgePrism`, `Aiora`, `QuikShipping`, `wet-mcp`, `oci-vm-prod`, etc.

This document specifies the work required to finish v0.1 to production quality, align the repo with the ecosystem template, merge or close the 27 open PRs, and validate that skret actually replaces Doppler/Infisical for the existing production stack.

Sections 2-5 assume the v0.1 design spec (`2026-04-05-skret-cli-design.md`) is the authoritative source of record for architecture, command surface, and provider abstractions. All cross-references use that spec's section numbers unless stated otherwise.

## 2. Current-state audit

### 2.1 Implementation matrix (v0.1 plan task → status)

| Task (plan 2026-04-06) | Spec §      | Files                                   | Code present | Tests | Coverage | Status         |
|------------------------|-------------|-----------------------------------------|--------------|-------|----------|----------------|
| T1 scaffold            | §12         | all repo-standard files                 | Yes          | n/a   | n/a      | Done w/ gaps   |
| T2 config schema       | §3          | `internal/config/schema.go`             | Yes          | Yes   | 96.6 %   | Done           |
| T3 config loader       | §3.2        | `internal/config/{loader,resolver}.go`  | Yes          | Yes   | 96.6 %   | Done           |
| T4 provider interface  | §2.3        | `internal/provider/{provider,registry}.go` | Yes       | Yes   | 100 %    | Done           |
| T5 local provider      | §5.2        | `internal/provider/local/local.go`      | Yes          | Yes   | 80.3 %   | Done, low cov. |
| T6 CLI foundation      | §4          | `internal/cli/root.go`, cobra setup     | Yes          | Yes   | 76.2 %   | Done, low cov. |
| T7 init command        | §4.1        | `internal/cli/init.go`                  | Yes          | Yes   | (cli)    | Done, `--force` missing |
| T8 get / env / list    | §4.3-4.7    | `internal/cli/{get,env,list}.go`        | Yes          | Yes   | (cli)    | Done           |
| T9 set / delete        | §4.5-4.6    | `internal/cli/{set,delete}.go`          | Yes          | Yes   | (cli)    | Done, `--force` alias missing |
| T10 run command        | §4.2        | `internal/cli/run.go`                   | Yes          | Yes   | (cli)    | Done           |
| T11 AWS SSM provider   | §5.1        | `internal/provider/aws/*.go`            | Yes          | Yes   | **65.2 %** | Done, coverage fail |
| T12 importers          | §6.1-6.3    | `internal/importer/*.go`                | Yes          | Yes   | 84.8 %   | Done, low cov. |
| T13 import command     | §4.8        | `internal/cli/import.go`                | Yes          | Yes   | (cli)    | Done           |
| T14 syncers            | §6.4-6.5    | `internal/syncer/*.go`                  | Yes          | Yes   | 81.7 %   | Done, low cov. |
| T15 sync command       | §4.9        | `internal/cli/sync.go`                  | Yes          | Yes   | (cli)    | Done           |
| T16 logging + errors   | §7          | `internal/logging/*.go`, error wrapping | Yes          | Yes   | 97.3 %   | Done           |
| T17 goreleaser + CI/CD | §9, §12.2   | `.goreleaser.yaml`, `.github/workflows/*` | Yes        | Yes   | n/a      | Done, untriggered |
| T18 docs site          | §11         | `docs/` VitePress                       | Partial      | n/a   | n/a      | **~30 %**      |
| T19 integration + E2E  | §10         | `tests/{integration,e2e}/`              | Yes          | Yes   | n/a      | Done, localstack only |

**Aggregate internal coverage:** 79.5 % (target 95 %). **`pkg/skret/` coverage:** 0 % (target 90 %, no test files).

### 2.2 Coverage breakdown (failing packages)

| Package                       | Coverage | Target | Gap      |
|-------------------------------|----------|--------|----------|
| `internal/cli`                | 76.2 %   | 95 %   | −18.8 pp |
| `internal/exec`               | 82.6 %   | 95 %   | −12.4 pp |
| `internal/importer`           | 84.8 %   | 95 %   | −10.2 pp |
| `internal/provider/aws`       | **65.2 %** | 95 % | **−29.8 pp** |
| `internal/provider/local`     | 80.3 %   | 95 %   | −14.7 pp |
| `internal/syncer`             | 81.7 %   | 95 %   | −13.3 pp |
| `pkg/skret`                   | 0 %      | 90 %   | **−90 pp** |

### 2.3 Scope deviations from v0.1 spec

| Deviation | Direction | Action |
|---|---|---|
| `internal/cli/history.go` added | Scope creep (v0.5 roadmap) | Move to v0.2, keep behind hidden flag OR delete & re-add in v0.2 |
| `internal/cli/rollback.go` added | Scope creep (v0.5 roadmap) | Same as above |
| Reference expansion (mentioned in commit 4e1c4c6) | Scope creep (v0.4 roadmap) | Verify if partially implemented and either finish + gate behind flag OR revert |
| `.infisical.json` required by spec §12.1 | Missing | Create or remove from spec — see §3.4 below |
| `skret init --force` flag (plan T7) | Missing on `main`, present in PR #30 via Palette | Merge PR #30 after commit-prefix rewrite |
| `skret delete --force` alias | Missing (only `--confirm` exists) | Alias `--force` to `--confirm` in `delete.go` |
| CI coverage gate at 80 % | Deviation from spec §10.3 (95 %) | Raise to 95 % after §4 coverage work completes |

### 2.4 Repository content deviations

Files at `./` that should not exist in a shipped repo:

- `skret.exe` — 14 MB binary committed to git. Already matched by `.gitignore` pattern `*.exe` but was force-added.
- `patch.py` — one-off migration script from an earlier session. Not referenced by any workflow.
- `patch_aws_interface.ps1` — same, PowerShell variant.

Files required by the v0.1 design spec §12.1 but missing:

- `.infisical.json` — spec §12.1 lists this as "required (bootstrap via Infisical until self-hosting)". Given skret's *purpose* is to replace Infisical, this entry in the spec is contradictory. **Resolution:** drop `.infisical.json` from the required list. skret bootstraps from environment variables only (see v0.1 spec §14 open question 4, already resolved as "always env vars, never config file").

### 2.5 Pull-request landscape

Snapshot 2026-04-11 12:30 ICT, repo `n24q02m/skret`:

- **30 PRs total** (27 OPEN, 3 CLOSED as renovate-autoclose).
- **Authors:** 22 user-authored (from Jules bot work pushed as user commits), 2 Renovate app, and multiple duplicate branches for the same logical fix.
- **Classes:**
  - **Refactor** (6 PRs): split long functions `newInitCmd`, `newListCmd`, `newSyncCmd`, `newSetCmd`, `newEnvCmd`, `newImportCmd`. All touch `internal/cli/*.go`.
  - **Security / Sentinel** (3 PRs): HTTP client timeout in Doppler/Infisical importers + GitHub syncer, insecure file permissions on generated config, unbounded default HTTP client.
  - **Performance / Bolt** (2 PRs): replace O(N) env lookup with O(1) map in `BuildEnv`, parallelize GitHub Actions secret syncing.
  - **Test coverage** (6 PRs): missing tests for Unix `Run`, Windows `Run`, `skret.Error`, `skret.Client`, `mapError` in AWS provider, `newSetCmd`.
  - **N+1 fixes** (2 PRs): GitHub syncer, import conflict resolution.
  - **Renovate** (2 OPEN): `actions/checkout@v6`, `golang.org/x/crypto v0.50.0`.
  - **Palette** (1 PR): add `--force` flag to `delete` command.
- **Commit prefix violations:** Jules PRs use `[FIX]`, `[TEST]`, `[CLEANUP]`, `⚡`, `🛡️`, `🎨` prefixes which violate the `fix:` / `feat:` only rule codified in skret `CLAUDE.md` and user global `CLAUDE.md`. Every PR must be amended or squash-merged with a rewritten subject line.
- **Duplication:** several logical fixes have 3-4 near-duplicate PRs because Jules regenerates branches on each invocation. Pick one per fix; close the rest with a short explanatory comment.

## 3. Template compliance

### 3.1 Reference repositories

The canonical templates are drawn from the MCP / tool subset of the production list (those already open-source and matched to a review-centric engineering flow): `wet-mcp`, `better-notion-mcp`, `better-email-mcp`, `better-godot-mcp`, `better-telegram-mcp`, `better-code-review-graph`, `mnemo-mcp`, `mcp-relay-core`, `claude-plugins`, `web-core`.

Product repos (`Aiora`, `KnowledgePrism`, `QuikShipping`, `LinguaSense`, `virtual-company`, `knowledge-core`) and infrastructure repos (`oci-vm-infra`, `oci-vm-prod`) do not ship with a CodeRabbit config today; they use different review flows (human review + CI only). skret, being a standalone tool repo, follows the tool template.

### 3.2 `.coderabbit.yaml` — REQUIRED

Byte-for-byte identical across all 10 tool-class prod repos audited:

```yaml
language: "en-US"
reviews:
  auto_review:
    enabled: true
    drafts: false
    ignore_usernames:
      - "n24q02m"
      - "dependabot[bot]"
      - "renovate[bot]"
      - "github-actions[bot]"
      - "devin-ai-integration[bot]"
      - "google-labs-jules[bot]"
  profile: "chill"
  request_changes_workflow: false
  high_level_summary: true
  auto_incremental_review: true
issue_enrichment:
  auto_enrich:
    enabled: true
  planning:
    enabled: true
chat:
  auto_reply: false
```

Rationale: `chill` profile keeps noise low on solo-maintained repos, `ignore_usernames` suppresses reviews of bot-authored PRs (Jules, Renovate, Sentinel, Bolt) where review would be redundant, `request_changes_workflow: false` prevents CodeRabbit from blocking merges, `high_level_summary: true` gives a one-line human-readable description per PR.

### 3.3 `.github/PULL_REQUEST_TEMPLATE.md` — REQUIRED

Copy verbatim from `wet-mcp/.github/PULL_REQUEST_TEMPLATE.md`. The template covers Description, Changes, Type of Change (bug/feature/breaking), Testing checklist, Screenshots, and a final checklist of coding standards.

### 3.4 `.github/ISSUE_TEMPLATE/` — REQUIRED

Two files copied from `wet-mcp/.github/ISSUE_TEMPLATE/`:

- `bug_report.md` — `Describe the bug`, `To Reproduce`, `Expected behavior`, `Screenshots`, `Environment` (must include `Go version` field for skret), `Additional context`.
- `feature_request.md` — `Is your feature request related to a problem?`, `Describe the solution you'd like`, `Describe alternatives you've considered`, `Additional context`.

### 3.5 `.github/best_practices.md` — EXPAND

Current file is 5 lines. Target structure (based on `wet-mcp/.github/best_practices.md`):

```markdown
# Style Guide - skret

## Architecture
Cloud-provider secret manager CLI wrapper. Go, single-binary distribution.

## Go
- Formatter: gofumpt (stricter than gofmt)
- Linter: golangci-lint (config in .golangci.yaml)
- Test: testing + testify, -race -cover ./...
- Module: Go 1.26+
- Core deps: Cobra, AWS SDK v2, slog, yaml.v3

## Code Patterns
- Context propagation: every provider method accepts context.Context
- Error wrapping: fmt.Errorf("op %q: %w", key, err) at each layer boundary
- Secret redaction: slog handler redacts known values; never log raw secret values
- Thin CLI, rich library: cmd/skret minimal, pkg/skret is the public surface
- Build-tagged platform code: exec_unix.go + exec_windows.go
- Atomic file writes: temp file + os.Rename for local provider
- File locking: flock (Unix), LockFileEx (Windows)

## Commits
Only `fix:` and `feat:` (never chore:, docs:, refactor:, ci:, build:, style:, perf:, test:).
Never use `!` breaking-change marker. Never `--no-verify`.

## Security
Never commit credentials. Use env vars only. SecureString + KMS for AWS SSM.
Validate all config paths. Filter `exclude:` keys from env injection.
```

### 3.6 Branch ruleset — UPDATE

Current skret `.github/rulesets/main.json` is 34 lines. Reference `wet-mcp/.github/rulesets/main.json` is 67 lines. Merge to a union that keeps skret's stricter review settings while adopting wet-mcp's additional rules:

- Keep: `deletion`, `non_fast_forward`, `required_linear_history`, `pull_request` (with `required_approving_review_count: 1`, `dismiss_stale_reviews_on_push: true`, `require_code_owner_review: true`).
- Adopt from wet-mcp: `update` rule, `code_quality` rule (severity errors), `code_scanning` rule (CodeQL high_or_higher), `allowed_merge_methods: [squash]` (squash-only merges enforce linear history and match the fix:/feat: commit style with a single subject line), `bypass_actors` for the admin role (actor_id 5).
- Keep skret's `require_last_push_approval: true` and `required_review_thread_resolution: true` (stricter than wet-mcp, appropriate for a secrets-management tool).

The synced ruleset is published via `gh api -X PUT /repos/n24q02m/skret/rulesets/<id>` in the plan.

### 3.7 Root hygiene

- Delete `skret.exe` from git history at HEAD (it's already ignored). Use `git rm --cached skret.exe && echo 'skret.exe' >> .gitignore` (the ignore pattern is already present but the file was force-added).
- Move `patch.py` and `patch_aws_interface.ps1` to `scripts/archive/` (preserving history) with a README noting they are one-off migration scripts not run in CI. If they are entirely obsolete, delete outright and reference the commit hash in the plan.
- Drop `.infisical.json` from the "required files" list in v0.1 spec §12.1. skret bootstraps from env vars only (already the declared behaviour in v0.1 spec §14 Q4).

## 4. Coverage & tests (spec §10.3 compliance)

### 4.1 Target matrix

| Package                       | Current  | Target | Gap      | Action |
|-------------------------------|----------|--------|----------|--------|
| `internal/cli`                | 76.2 %   | 95 %   | −18.8 pp | Add tests for init `--force`, delete `--force`/`--confirm`, env format=export, list values+confirm, history/rollback |
| `internal/exec`               | 82.6 %   | 95 %   | −12.4 pp | Test Windows-only path (env injection edge cases, signal forwarding) |
| `internal/importer`           | 84.8 %   | 95 %   | −10.2 pp | Table-driven tests for Doppler pagination, Infisical machine-identity auth flow, dotenv multi-line values |
| `internal/provider/aws`       | **65.2 %** | 95 % | **−29.8 pp** | Test error mapping (ParameterNotFound, Throttling, AccessDenied, ValidationException), KMS encryption context, list pagination over >50 params, PutParameter overwrite path |
| `internal/provider/local`     | 80.3 %   | 95 %   | −14.7 pp | Test concurrent write (file lock), atomic write rollback on partial failure, malformed YAML |
| `internal/syncer`             | 81.7 %   | 95 %   | −13.3 pp | Test GitHub public-key caching, sealing edge cases, dotenv escaping edge cases (newlines, quotes, backslashes) |
| `pkg/skret`                   | 0 %      | 90 %   | **−90 pp** | Create `client_test.go` and `errors_test.go` — drive the public surface from outside |

### 4.2 Test-type gates

- Unit: `go test -race -cover ./internal/...` — CI job, must hit each package threshold.
- Integration: `go test -tags=integration ./tests/integration/...` using LocalStack (SSM emulator) — Docker-composed in CI.
- E2E: `go test -tags=e2e ./tests/e2e/...` — invokes the built binary via `os/exec`, covers all 9 commands.
- Property-based: `testing/quick` for `pathKeyToEnvVar` (path → env var name) and dotenv parser.
- Fuzz: `go test -fuzz=FuzzDotenvParser -fuzztime=30s ./internal/importer/` — catch dotenv edge cases.

### 4.3 CI coverage gate

Raise the ci.yml threshold from **80 → 95 %** on `internal/…` only after §4.1 work lands. Add a second gate at **90 %** on `pkg/skret` once the public API is covered. Use `go tool cover -func` + awk, fail the job under threshold.

## 5. CI / CD / release workflow

### 5.1 `ci.yml` updates

- Add `harden-runner` (step-security) pin step to the ubuntu lint/test/security jobs.
- Bump `actions/checkout@v4` → `@v6` (Renovate PR #22 already prepared).
- Bump `actions/setup-go@v5` stays current.
- Add the 95 % coverage gate (§4.3).
- Add a `govulncheck` job (`golang.org/x/vuln/cmd/govulncheck ./...`) — separate from CodeQL, catches supply-chain CVEs at build time.
- Add a `gitleaks` job — fails on any secret-like string accidentally committed.
- Keep `CodeQL` (`security` job).

### 5.2 `cd.yml` (tag push)

Already correct: goreleaser with cosign keyless + syft SBOM + ghcr.io docker push. No changes needed other than verifying it actually succeeds on a test tag (`v0.0.1-alpha.1`) before `v0.1.0` ships.

### 5.3 `release.yml` (workflow_dispatch)

Already wires `python-semantic-release@v8` with stable/beta choice. The problem is it has never been executed: `CHANGELOG.md` is empty. First run must:

1. Set a starting version (e.g. `v0.1.0-alpha.1`) via `--force` flag OR seed `CHANGELOG.md` with the Conventional Commits parser reading from the initial commit.
2. Verify the tag push triggers `cd.yml` which in turn publishes to ghcr.io and creates the GitHub release with binaries.
3. Cross-check that `semantic-release.toml` commit-types list includes only `fix` and `feat` (matching the skret commit rule) — today semantic-release defaults include chore/docs/etc. which skret forbids.

### 5.4 PR-title enforcement

Add `.github/workflows/pr-title.yml`:

```yaml
name: PR Title Lint
on:
  pull_request:
    types: [opened, edited, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: amannn/action-semantic-pull-request@v5
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          types: |
            fix
            feat
          requireScope: false
          subjectPattern: ^(?![A-Z]).+$
          subjectPatternError: |
            The subject must not start with an uppercase character.
```

This rejects PR titles like `[FIX] Function newInitCmd is too long`, `⚡ Bolt: …`, `🛡️ Sentinel: …` at PR-open time.

## 6. PR triage strategy

### 6.1 Principles

- **Never bulk close** (user rule `feedback_never_bulk_close.md`): read every diff before closing any PR.
- **Interactive** (user rule `feedback_pr_review_process.md`): user approves each merge/close decision in advance; the plan (§7) records one approval per PR.
- **Commit prefix rewrite** (user rule `feedback_commit_prefix.md`): every PR must be merged with a `fix:` or `feat:` subject line. Squash-merge allows editing the subject at merge time, so this is mechanically achievable without force-pushes to the source branch.
- **Deduplicate**: pick one PR per logical fix, close the rest with a comment citing the chosen PR.

### 6.2 Triage table (decision required by user before execution)

| # | Author  | Title                                                      | Class    | Decision     | Notes |
|---|---------|------------------------------------------------------------|----------|--------------|-------|
| 5 | Bolt    | Replace O(N) env lookup with O(1) map                      | perf     | MERGE as `feat:` | Canonical Bolt PR |
| 6 | Sentinel| Fix Unbounded Default HTTP Client                          | security | MERGE as `fix:` | Canonical Sentinel PR |
| 7 | Jules   | Function newEnvCmd is too long                             | refactor | MERGE as `fix:` | Pick shortest diff |
| 8 | Jules   | Untested mapError in AWS provider                          | test     | MERGE as `feat:` (adds tests → new behavior) | Helps AWS coverage |
| 9 | Jules   | Function newListCmd is too long                            | refactor | MERGE as `fix:` | |
| 10| Jules   | Function newInitCmd is too long                            | refactor | MERGE as `fix:` | |
| 11| Jules   | Missing tests for Unix Run                                 | test     | MERGE as `feat:` | |
| 12| Bolt    | Inefficient loop in BuildEnv env lookup                    | perf     | CLOSE as duplicate of #5 | |
| 13| Jules   | Function newSetCmd is too long                             | refactor | MERGE as `fix:` | |
| 14| Sentinel| HTTP client timeout in importers+syncer                    | security | CLOSE as duplicate of #6 | |
| 15| Jules   | Missing tests for skret.Error                              | test     | MERGE as `feat:` | Helps pkg/skret coverage |
| 16| Jules   | N+1 in import.go Conflict Resolution                       | perf     | MERGE as `fix:` | |
| 17| Jules   | N+1 HTTP Request in GitHub Syncer                          | perf     | MERGE as `fix:` | |
| 18| Jules   | Missing tests for Windows Run                              | test     | MERGE as `feat:` | |
| 19| Jules   | Function newImportCmd is too long                          | refactor | MERGE as `fix:` | |
| 20| Sentinel| Insecure file permissions on generated config              | security | MERGE as `fix:` | |
| 21| Renovate| golang.org/x/crypto v0.50.0                                | deps     | MERGE as `fix:` | |
| 22| Renovate| actions/checkout v6                                        | deps     | MERGE as `fix:` | |
| 23| Sentinel| HTTP timeout in github syncer getPublicKey                 | security | CLOSE as duplicate of #6 | |
| 24| Sentinel| HTTP timeout in infisical importer                         | security | CLOSE as duplicate of #6 | |
| 25| Sentinel| HTTP timeout in HTTP requests (general)                    | security | CLOSE as duplicate of #6 | |
| 26| Jules   | Missing tests for skret.Client                             | test     | MERGE as `feat:` | |
| 27| Jules   | Function newSyncCmd is too long                            | refactor | MERGE as `fix:` | |
| 28| Sentinel| [CRITICAL] Fix Missing HTTP Client Timeout                 | security | CLOSE as duplicate of #6 | |
| 29| Bolt    | Parallelize github actions secret syncing                  | perf     | MERGE as `feat:` | New parallelism behavior |
| 30| Palette | Support `--force` flag alongside `--confirm` for delete    | feature  | MERGE as `feat:` | |

Final counts: **17 merged, 6 closed as duplicates, 4 closed as superseded by direct fix**. The user must approve this matrix (or amend it) before execution — the plan does not auto-execute the merges.

### 6.3 Merge order

To minimize rebase conflicts:

1. Deps first (#21, #22) — smallest diffs, unblock security scans.
2. Security single-source fix (#6, #20) — most likely to merge cleanly.
3. Perf (#5, #29, #16, #17) — independent.
4. Tests (#8, #11, #15, #18, #26) — additive, low conflict risk.
5. Refactor-split (#7, #9, #10, #13, #19, #27) — overlapping files; merge sequentially, rebase between each.
6. Feature (#30) — last, independent file changes.

## 7. Integration testing with production repos

### 7.1 Scope

The 17 consumer production repos plus skret itself (= 18):

1. KnowledgePrism, 2. Aiora, 3. QuikShipping, 4. LinguaSense, 5. virtual-company, 6. knowledge-core, 7. web-core, 8. oci-vm-infra, 9. oci-vm-prod, 10. wet-mcp, 11. better-telegram-mcp, 12. better-godot-mcp, 13. better-notion-mcp, 14. better-email-mcp, 15. better-code-review-graph, 16. mnemo-mcp, 17. mcp-relay-core.

(claude-plugins, jules-task-archiver, qwen3-embed, modalcom-ai-workers consume no secrets directly and are excluded. `virtual-company` is an app container inside oci-vm-infra and shares its secrets.)

### 7.2 Phase A — dry-run per repo

For each repo:

1. `skret init --provider=aws --path=/<repo-slug>/<env> --region=ap-southeast-1` to generate a candidate `.skret.yaml`.
2. `skret import --from=doppler --doppler-project=<project> --doppler-config=<env> --to-path=/<repo-slug>/<env> --dry-run` or `--from=infisical` equivalent, captures the diff to `tmp/migration/<repo>.txt`.
3. Human review of the diff — detect any secrets that must NOT leave Doppler/Infisical for compliance reasons.
4. No writes. No changes to the consumer repo yet.

### 7.3 Phase B — staging adoption

For each repo, in this sequence: `knowledge-core → wet-mcp → better-code-review-graph → mnemo-mcp → mcp-relay-core → better-notion-mcp → better-email-mcp → better-telegram-mcp → better-godot-mcp → LinguaSense → oci-vm-infra → oci-vm-prod → web-core → virtual-company → QuikShipping → Aiora → KnowledgePrism` (low-risk infra and MCP servers first, consumer apps last):

1. Real `skret import` into AWS SSM (not dry-run).
2. Update the consumer repo's `Makefile`: replace `doppler run --` / `infisical run --` with `skret run -- ` in **staging** targets only (`make up-staging-<service>`). Keep `doppler run` for prod targets.
3. Open a PR on the consumer repo titled `feat(secrets): add skret run to staging targets`.
4. Run the staging target on the appropriate VM (`infra-vnic` for infra repos, `prod-vnic` staging profile for app repos). Verify the service starts and the health check passes.
5. Wait 48 h for any delayed issues (secret drift, missing keys, encoding problems).
6. Move to the next repo in sequence.

### 7.4 Phase C — production cutover

After all 17 staging targets pass Phase B and 7 days of staging observation:

1. Per repo, switch prod target too: `doppler run --` → `skret run -- ` (same PR structure).
2. Roll out repo-by-repo, 24 h between each, watching logs and billing dashboards.
3. When all 17 repos are on skret, cancel Doppler paid plan and archive the Infisical self-host instance (snapshot first for rollback).

### 7.5 Observability for rollout

- AWS CloudTrail logs every SSM `GetParameter*` call — set up a CloudWatch metric filter alerting on `errorCode != null` for `ssm.amazonaws.com` events.
- Per repo: record baseline cold-start of the consumer service with Doppler vs with skret. Spec §1.4 targets `< 50 ms` for skret get cold-start — verify end-to-end latency does not regress the consumer service startup by more than 5 % (p95).
- KMS budget monitor: alert if monthly `kms:Decrypt` calls exceed 18 000 (90 % of the 20 000 free-tier limit).

### 7.6 Rollback plan

If Phase B or C fails on any repo:

1. Revert the consumer repo's Makefile change (single commit, single file).
2. Restore `doppler run --` in both targets.
3. File an issue on `n24q02m/skret` titled `fix: integration failure for <repo>` with repro steps.
4. Keep the SSM parameter path intact (no destructive rollback on AWS) — it's a no-op for consumers that no longer reference it.

## 8. Docs completeness (spec §11.2)

Current `docs/` covers: index, guide/{getting-started, installation, configuration}, migration/{doppler, infisical, dotenv}, providers/{aws, local}. Missing per spec §11.2:

- `guide/authentication.md` — AWS credential chain, IAM role setup, OIDC for GitHub Actions.
- `guide/troubleshooting.md` — common errors, exit code table, debug log tips.
- `commands/{init,run,get,env,set,delete,list,import,sync}.md` — one page per command, auto-generated from `cobra/doc` (new `skret docs generate` subcommand).
- `integrations/github-actions.md` — OIDC setup + sync workflow example.
- `integrations/oci-vms.md` — IAM Roles Anywhere setup for VMs (infra-vnic, prod-vnic).
- `integrations/makefile-patterns.md` — the exact replacements used in §7 integration rollout.
- `integrations/docker-compose.md` — pattern for `skret run -- docker compose up`.
- `cookbook/{rotating-keys,multi-region-sync,team-access,backup-restore}.md`.
- `reference/cli.md` — full CLI flag reference (auto-generated).
- `reference/config-schema.md` — JSON/YAML schema generated from Go structs via `invopop/jsonschema`.
- `reference/error-codes.md` — exit code table from spec §7.1.
- `reference/library-api.md` — link to pkg.go.dev with a short usage example.
- `contributing/{setup,adding-provider,adding-importer,release-process}.md`.
- `faq.md` — why skret vs Doppler/Infisical, free-tier math, KMS cost, cross-platform caveats.

Plan §5 builds these in two passes: auto-generated reference first, human-written guides second.

## 9. Success criteria

All of the following must hold before tagging `v0.1.0`:

1. `main` contains all merged PRs from the triage matrix (§6.2), with every commit subject matching `^(fix|feat)(\(.*\))?: .+$`.
2. `go test -race -cover ./...` passes on ubuntu, macos, windows.
3. Per-package coverage meets §4.1 thresholds.
4. CI coverage gate at 95 % (internal/), 90 % (pkg/) is green.
5. `.coderabbit.yaml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md` exist and match §3.2–§3.4.
6. `.github/best_practices.md` contains the §3.5 content.
7. `.github/rulesets/main.json` matches §3.6; the ruleset is also active on GitHub (`gh api /repos/n24q02m/skret/rulesets` returns enforcement: active).
8. Root contains no `skret.exe`, no `patch.py`, no `patch_aws_interface.ps1`.
9. `.github/workflows/pr-title.yml` exists and has rejected at least one test-case malformed title.
10. `CHANGELOG.md` has at least one non-header section, populated by `python-semantic-release` on a dry-run tag.
11. `docs/` contains every file listed in §8 and VitePress build (`cd docs && pnpm build`) succeeds without broken links.
12. `docs/superpowers/specs/2026-04-05-skret-cli-design.md` §12.1 is amended to drop `.infisical.json`.
13. At least 3 consumer prod repos have completed Phase B of §7 (wet-mcp, better-code-review-graph, mnemo-mcp as smoke-test candidates) with no observed regression.
14. `skret version` reports a real commit SHA and build timestamp (goreleaser-injected `version.Version`, `version.Commit`, `version.Date` instead of the current `0.0.0-dev / none / unknown`).
15. A `v0.0.1-alpha.1` dry-run tag has been pushed and the CD workflow has published the resulting artifacts to ghcr.io and GitHub Releases without human intervention.

## 10. Out of scope (for this hardening spec)

- Any new provider (GCP, Cloudflare, Azure, OCI) — spec v0.1 §13 keeps these in v0.2+.
- `skret gen`, `skret diff`, `skret rotate`, `skret audit` — v0.2+ commands.
- Secret references / templates — v0.4+.
- Dynamic secrets / history / rollback as production features — see §2.3 about reverting the accidental v0.5 code.
- Homebrew tap / Scoop bucket / APT repo publication — handled by the existing `cd.yml` goreleaser pipeline; this spec assumes the pipeline works and verifies it with the alpha tag in §9 criterion 15.

## 11. Risks & mitigations

| Risk                                                       | Likelihood | Impact | Mitigation |
|------------------------------------------------------------|------------|--------|------------|
| Rewriting Jules commit prefixes via squash-merge introduces author attribution loss | High | Low | GitHub squash-merge preserves co-authorship; add `Co-authored-by: google-labs-jules[bot]` to the squash commit body. |
| Sequential PR merges create rebase conflicts in `internal/cli/` | High | Medium | Merge refactor PRs in a single order, rebase after each, let CI revalidate. |
| CodeRabbit suddenly starts reviewing Jules PRs (after §3.2 lands) and generates noise | Medium | Low | `ignore_usernames` already includes `google-labs-jules[bot]` — verified. |
| Phase B integration test on `KnowledgePrism` reveals a missing secret in AWS SSM that Doppler had | Medium | High | Dry-run diff in Phase A catches this before writes; manual review required per §7.2. |
| `python-semantic-release` fails on first run due to malformed commit history (prefixes other than fix/feat on `main`) | High | Low | Pre-run `git log --oneline main` and amend the 3 commits violating (`ci:`, `test(integration):`, `fix(test):`, `chore(repo):`) before tagging. |
| Raising coverage gate to 95 % blocks merge of valid PRs | Low | Medium | Phase coverage work into §4 before enabling the 95 % gate; keep gate at 80 % until then. |
| `skret run` on Windows consumer repos (none today) exposes a signal-forwarding bug | Low | Medium | `internal/exec/exec_windows.go` has reduced coverage — §4 adds tests for the Windows path. |
| Cancelling Doppler before all 17 repos cut over | Low | High | §7.4 explicitly requires completing Phase C for every repo with a 7-day observation window before cancellation. |

## 12. Open questions

1. **Scope creep revert vs forward-port.** Should `history` and `rollback` (Apr 9 commit `4e1c4c6`) be reverted and re-introduced in v0.2, or hidden behind a `--experimental` flag in v0.1? **Proposal:** hide behind `--experimental` since tests already exist and removing then re-adding risks regression.

2. **Docs hosting.** `skret.n24q02m.com` requires a DNS record and GitHub Pages setup. **Proposal:** use `n24q02m.github.io/skret` as a fallback for v0.1 shipping, move to the custom domain in v0.2.

3. **Integration test authority.** Who approves Phase B/C rollout on each consumer repo? **Proposal:** user approval per-repo, recorded in the plan as a manual gate before each Phase B step.

4. **CodeRabbit cost.** CodeRabbit is free for open-source repos. skret is public, so there's no billing concern. Confirmed, no open question.

---

**End of hardening spec.**
