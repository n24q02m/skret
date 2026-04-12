# skret v0.1 Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` to run this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking. Every step is meant to be verified before the next starts — `feedback_verify_completeness.md` applies.

**Goal:** Take skret from its current mid-stream state (79.5 % coverage, 27 open PRs, template gaps, empty CHANGELOG, no real-world prod adoption) to a shipped, template-compliant, production-validated `v0.1.0` release adopted by all 17 consumer production repositories.

**Spec:** `docs/superpowers/specs/2026-04-11-skret-v01-hardening.md` (this plan's parent), referencing the original design `docs/superpowers/specs/2026-04-05-skret-cli-design.md`.

**Starting conditions (verified 2026-04-11 ICT):**
- `main` at `19aec0b`, 19 author-n24q02m commits only, clean working tree.
- `go test -race ./...` passes; aggregate internal coverage 79.5 %.
- 27 open PRs, 3 closed.
- Template files missing: `.coderabbit.yaml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/*`.
- Root junk files: `skret.exe`, `patch.py`, `patch_aws_interface.ps1`.
- CHANGELOG empty.

---

## Dependency graph

```
Phase 1 (Template compliance)
  ├─ Task 1.1 .coderabbit.yaml
  ├─ Task 1.2 PR/Issue templates
  ├─ Task 1.3 best_practices.md expansion
  ├─ Task 1.4 Ruleset update
  ├─ Task 1.5 pr-title workflow
  └─ Task 1.6 Root hygiene (junk cleanup)
       └─ Phase 2 (PR triage)
            ├─ Task 2.1 Deps PRs (#21, #22)
            ├─ Task 2.2 Security (#6, #20) + close duplicates
            ├─ Task 2.3 Perf (#5, #29, #16, #17)
            ├─ Task 2.4 Tests (#8, #11, #15, #18, #26)
            ├─ Task 2.5 Refactor (#7, #9, #10, #13, #19, #27)
            └─ Task 2.6 Feature (#30)
                 └─ Phase 3 (Spec deviations & coverage)
                      ├─ Task 3.1 Scope-creep gate (history/rollback)
                      ├─ Task 3.2 AWS provider tests (65 → 95 %)
                      ├─ Task 3.3 cli tests (76 → 95 %)
                      ├─ Task 3.4 importer / exec / local / syncer tests
                      ├─ Task 3.5 pkg/skret tests (0 → 90 %)
                      ├─ Task 3.6 Raise CI gate to 95/90
                      └─ Task 3.7 Spec §12.1 amendment
                           └─ Phase 4 (Docs completeness)
                                ├─ Task 4.1 Auto-generated reference
                                ├─ Task 4.2 guide/authentication + troubleshooting
                                ├─ Task 4.3 integrations/*
                                ├─ Task 4.4 cookbook/*
                                ├─ Task 4.5 reference/*
                                ├─ Task 4.6 contributing/*
                                └─ Task 4.7 faq + VitePress build
                                     └─ Phase 5 (Integration testing)
                                          ├─ Task 5.1 Phase A dry-run (17 repos)
                                          ├─ Task 5.2 Phase B staging adoption (17)
                                          └─ Task 5.3 Phase C prod cutover (17)
                                               └─ Phase 6 (Release)
                                                    ├─ Task 6.1 CHANGELOG seed
                                                    ├─ Task 6.2 v0.0.1-alpha.1 dry-run tag
                                                    ├─ Task 6.3 Fix any CD findings
                                                    ├─ Task 6.4 v0.1.0 release
                                                    └─ Task 6.5 Doppler / Infisical decommission
```

---

## Phase 1 — Template compliance

### Task 1.1 — Add `.coderabbit.yaml`

**Files:** create `.coderabbit.yaml` at repo root.

- [ ] Copy from reference repo `projects/wet-mcp/.coderabbit.yaml` (byte-identical across the tool subset of prod repos — already verified Apr 11).

  ```bash
  cp "C:/Users/n24q02m-wlap/projects/wet-mcp/.coderabbit.yaml" \
     "C:/Users/n24q02m-wlap/projects/skret/.coderabbit.yaml"
  diff "C:/Users/n24q02m-wlap/projects/wet-mcp/.coderabbit.yaml" \
       "C:/Users/n24q02m-wlap/projects/skret/.coderabbit.yaml"
  # expect: no output
  ```

- [ ] Verify the 6 bot usernames in `ignore_usernames` are still correct (`n24q02m`, `dependabot[bot]`, `renovate[bot]`, `github-actions[bot]`, `devin-ai-integration[bot]`, `google-labs-jules[bot]`). If Sentinel/Bolt/Palette need to be added, do so here; they appear to run under user identity today so no additional entries needed.

- [ ] Commit with subject `feat: add CodeRabbit config`. Pre-commit MUST succeed (do not `--no-verify`).

**Acceptance:** file exists, `diff` against `wet-mcp/.coderabbit.yaml` is empty, commit lands on `main`.

### Task 1.2 — Add PR & issue templates

**Files:** create `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`.

- [ ] Copy `PULL_REQUEST_TEMPLATE.md`:

  ```bash
  cp "C:/Users/n24q02m-wlap/projects/wet-mcp/.github/PULL_REQUEST_TEMPLATE.md" \
     "C:/Users/n24q02m-wlap/projects/skret/.github/PULL_REQUEST_TEMPLATE.md"
  ```

- [ ] Create `.github/ISSUE_TEMPLATE/` and copy both issue templates:

  ```bash
  mkdir -p "C:/Users/n24q02m-wlap/projects/skret/.github/ISSUE_TEMPLATE"
  cp "C:/Users/n24q02m-wlap/projects/wet-mcp/.github/ISSUE_TEMPLATE/bug_report.md" \
     "C:/Users/n24q02m-wlap/projects/skret/.github/ISSUE_TEMPLATE/bug_report.md"
  cp "C:/Users/n24q02m-wlap/projects/wet-mcp/.github/ISSUE_TEMPLATE/feature_request.md" \
     "C:/Users/n24q02m-wlap/projects/skret/.github/ISSUE_TEMPLATE/feature_request.md"
  ```

- [ ] Edit `bug_report.md` Environment section to replace Python-specific lines with Go-specific ones: `- OS: [macOS / Linux / Windows]`, `- Go version: [output of go version]`, `- skret version: [output of skret --version]`, `- Installation method: [go install / Docker / brew / scoop / apt / direct]`.

- [ ] Commit: `feat: add PR and issue templates`.

**Acceptance:** the three files exist, `bug_report.md` Environment field matches Go toolchain, commit lands.

### Task 1.3 — Expand `.github/best_practices.md`

**Files:** rewrite `.github/best_practices.md`.

- [ ] Replace content with the §3.5 block from the hardening spec. The file grows from 5 lines → ~30 lines.

- [ ] Verify it matches the spec's target structure (sections: Architecture, Go, Code Patterns, Commits, Security).

- [ ] Commit: `feat: expand best practices with Go patterns`.

**Acceptance:** the file contains the Commits section with `Only fix: and feat:` explicitly stated, and the Code Patterns section mentions context propagation, error wrapping, redaction, build-tagged exec, atomic write, file locking.

### Task 1.4 — Update branch ruleset

**Files:** rewrite `.github/rulesets/main.json`, then push to GitHub via API.

- [ ] Merge the current skret ruleset (strict review settings) with the wet-mcp ruleset (extra rule types) into a union. Target content (produce this as the new file content):

  ```json
  {
    "name": "Main Branch Rules",
    "target": "branch",
    "source_type": "Repository",
    "source": "n24q02m/skret",
    "enforcement": "active",
    "bypass_actors": [
      {
        "actor_id": 5,
        "actor_type": "RepositoryRole",
        "bypass_mode": "always"
      }
    ],
    "conditions": {
      "ref_name": {
        "exclude": [],
        "include": ["refs/heads/main"]
      }
    },
    "rules": [
      { "type": "deletion" },
      { "type": "non_fast_forward" },
      { "type": "required_linear_history" },
      { "type": "update" },
      {
        "type": "pull_request",
        "parameters": {
          "required_approving_review_count": 1,
          "dismiss_stale_reviews_on_push": true,
          "require_code_owner_review": true,
          "require_last_push_approval": true,
          "required_review_thread_resolution": true,
          "allowed_merge_methods": ["squash"]
        }
      },
      {
        "type": "code_quality",
        "parameters": { "severity": "errors" }
      },
      {
        "type": "code_scanning",
        "parameters": {
          "code_scanning_tools": [
            {
              "tool": "CodeQL",
              "security_alerts_threshold": "high_or_higher",
              "alerts_threshold": "errors"
            }
          ]
        }
      }
    ]
  }
  ```

- [ ] Commit: `feat: align branch ruleset with ecosystem template`.

- [ ] Sync to GitHub via API. Get current ruleset id first:

  ```bash
  gh api repos/n24q02m/skret/rulesets --jq '.[] | select(.name=="Main Branch Rules") | .id'
  # capture id, then:
  RULESET_ID=<id>
  gh api -X PUT "repos/n24q02m/skret/rulesets/$RULESET_ID" \
    --input .github/rulesets/main.json
  ```

- [ ] Verify enforcement is active:

  ```bash
  gh api "repos/n24q02m/skret/rulesets/$RULESET_ID" --jq .enforcement
  # expect: "active"
  ```

**Acceptance:** file matches target JSON, GitHub ruleset API returns matching rules array and `enforcement: active`.

### Task 1.5 — PR title enforcement workflow

**Files:** create `.github/workflows/pr-title.yml`.

- [ ] Write the workflow per hardening spec §5.4. Use `amannn/action-semantic-pull-request@v5` pinned to the major version.

- [ ] Test the workflow by opening a scratch PR with a violating title (e.g. `[FIX] example`). The PR title lint must fail. Then fix the title and verify it passes. Close the scratch PR.

- [ ] Commit: `feat: enforce fix/feat commit prefix on PR titles`.

**Acceptance:** workflow file exists, scratch PR demonstration documented in the plan comments, workflow has run at least once.

### Task 1.6 — Root hygiene

**Files:** remove `skret.exe`, `patch.py`, `patch_aws_interface.ps1`.

- [ ] Remove the binary:

  ```bash
  cd "C:/Users/n24q02m-wlap/projects/skret"
  git rm --cached skret.exe
  rm -f skret.exe
  ```

  Pattern `*.exe` already in `.gitignore` (verified Apr 11).

- [ ] Remove the ad-hoc scripts. First inspect them for any useful logic:

  ```bash
  head -30 patch.py
  head -30 patch_aws_interface.ps1
  ```

  If they contain no logic needed going forward: `git rm patch.py patch_aws_interface.ps1`. If any logic is needed, move to `scripts/archive/` with a README explaining origin and why it's retained.

- [ ] Commit: `fix: remove committed binary and ad-hoc patch scripts`.

- [ ] Rebuild the binary and verify the build still works from a clean tree:

  ```bash
  go build -o skret.exe ./cmd/skret
  ./skret.exe --version
  ```

  Confirm `.gitignore` now keeps it out of `git status`:

  ```bash
  git status --porcelain
  # expect: no entry for skret.exe
  ```

**Acceptance:** binary and patch scripts absent from `git ls-files`, `.gitignore` keeps the rebuilt binary out of `git status`, `./skret.exe --version` still prints version info.

---

## Phase 2 — PR triage & merge

> **Gate:** the user must approve the triage matrix (§6.2 of the hardening spec) before Phase 2 begins. The plan does not auto-merge. For each task below, the executing agent must open the PR in browser / `gh pr view <n>` and confirm the diff before clicking merge.

### Task 2.1 — Deps PRs

- [ ] `gh pr view 22` — review `actions/checkout@v6` diff.
- [ ] `gh pr merge 22 --squash --subject "fix: bump actions/checkout to v6"`. Verify CI is green first.
- [ ] `gh pr view 21` — review `golang.org/x/crypto v0.50.0` diff.
- [ ] `gh pr merge 21 --squash --subject "fix(deps): bump golang.org/x/crypto to v0.50.0"`. Note: `fix(deps):` scope is allowed under the fix/feat rule; verify `pr-title.yml` accepts it.

**Acceptance:** both PRs merged, `main` HEAD builds clean.

### Task 2.2 — Security PRs (single-source)

- [ ] Pick canonical Sentinel PR (#6 `Fix Unbounded Default HTTP Client`). Review diff.
- [ ] If #6's diff already covers importers + syncer + getPublicKey: merge #6 as `fix: add HTTP client timeouts to all external callers`; then close #14, #23, #24, #25, #28 with comments `closed as superseded by #6`.
- [ ] If #6's diff is narrower (only default client): merge #6 first, then pick the smallest of #14/#23/#24/#25/#28 that covers the remaining call sites and merge as `fix: add HTTP timeout to remaining callers`, closing the others.
- [ ] Merge #20 (`Insecure file permissions on generated configuration`) as `fix: use 0600 permissions for generated config file`.

**Acceptance:** `grep -rn "&http.Client{}" internal/` returns no raw default clients; generated config files land at mode `0600`; related PRs closed with explanatory comments.

### Task 2.3 — Perf PRs

- [ ] Merge #5 (`Replace O(N) env lookup with O(1) map lookup`) as `feat: use map-backed env lookup in BuildEnv`. Close #12 as duplicate.
- [ ] Merge #29 (`parallelize github actions secret syncing`) as `feat: parallelize github actions secret sync`.
- [ ] Merge #16 (`N+1 Problem in import.go`) as `fix: avoid N+1 HTTP during import conflict resolution`.
- [ ] Merge #17 (`N+1 HTTP Request in GitHub Syncer`) as `fix: batch public-key fetch in github syncer`.

**Acceptance:** `go test -race ./...` green after each merge; BuildEnv microbench (if the test includes one) shows faster or equal latency; import + sync both complete with fewer HTTP calls than before.

### Task 2.4 — Test-coverage PRs

- [ ] Merge in order: #8 (AWS mapError), #11 (Unix Run), #18 (Windows Run), #15 (skret.Error), #26 (skret.Client).
- [ ] After each merge, re-run `go test -coverprofile=cov.out ./internal/... ./pkg/...` and record the new aggregate.
- [ ] Verify `pkg/skret` now has non-zero coverage after #15 + #26.

**Acceptance:** aggregate internal coverage strictly higher than baseline 79.5 %, pkg/skret coverage > 0.

### Task 2.5 — Refactor-split PRs

Merge order chosen to minimize rebase pain: sequential, rebase between each, CI re-run.

- [ ] #7 `newEnvCmd is too long` → `fix: split newEnvCmd into helpers`.
- [ ] #9 `newListCmd is too long` → `fix: split newListCmd into helpers`.
- [ ] #10 `newInitCmd is too long` → `fix: split newInitCmd into helpers`.
- [ ] #13 `newSetCmd is too long` → `fix: split newSetCmd into helpers`.
- [ ] #19 `newImportCmd is too long` → `fix: split newImportCmd into helpers`.
- [ ] #27 `newSyncCmd is too long` → `fix: split newSyncCmd into helpers`.

After each: `go build ./... && go test -race ./...`.

**Acceptance:** all six PRs merged, no function in `internal/cli/` exceeds `gocognit` / `gocyclo` default thresholds (enforced by golangci-lint).

### Task 2.6 — Palette feature PR

- [ ] `gh pr view 30` — review the `--force` flag patch for `delete`.
- [ ] Verify the spec alignment: design spec §4.6 references `--confirm` to skip the prompt; the new `--force` should be an alias for `--confirm`. Confirm no divergent semantics.
- [ ] Merge as `feat: support --force alias for delete command`.
- [ ] Also apply the same alias to `init --force` if not already present (plan Task 1 of original plan step 11 referenced `--force`). Write a follow-up commit if needed: `feat: support --force for init command`.

**Acceptance:** `skret delete KEY --force` works without prompt; `skret init --force` overwrites existing `.skret.yaml`; help text lists both flags.

---

## Phase 3 — Spec deviations & coverage work

### Task 3.1 — Scope-creep gate for history/rollback

- [ ] Review `internal/cli/history.go` + `internal/cli/rollback.go` and the corresponding tests. Determine if they actually work or are scaffolding only.
- [ ] Decision (per spec §2.3): hide behind `--experimental` flag on the root Cobra command. Add a check in `history.go` + `rollback.go` that returns `ErrNotEnabled` unless `SKRET_EXPERIMENTAL=1` or `--experimental` is set.
- [ ] Update tests to set the env var before calling these commands.
- [ ] Update `docs/` references if any (likely none).
- [ ] Commit: `feat: gate history and rollback behind --experimental flag`.

**Acceptance:** `skret history KEY` prints `error: history is experimental, set SKRET_EXPERIMENTAL=1`; `SKRET_EXPERIMENTAL=1 skret history KEY` still works.

### Task 3.2 — AWS provider test coverage (65.2 → 95 %)

**Files:** add `internal/provider/aws/aws_test.go` extensions, `internal/provider/aws/errors_test.go`.

- [ ] Table-driven test for error mapping: given AWS SDK error codes `ParameterNotFound`, `ParameterAlreadyExists`, `ThrottlingException`, `AccessDeniedException`, `ValidationException`, assert the mapped skret error type and the wrapped message.
- [ ] Test KMS encryption context passthrough: mock the SSM client, call `Get(ctx, key)`, assert the `WithDecryption=true` parameter and the correct KMS alias is used when `kms_key_id` is configured.
- [ ] Test `List(ctx, path)` pagination: mock responses with `NextToken` over 3 pages containing 60+ parameters total; assert the full list is returned in order.
- [ ] Test `Set(ctx, key, value, meta)` overwrite path: PutParameter with `Overwrite=true`, `Type=SecureString`, and tags mapped from `meta.Tags`.
- [ ] Test `Delete(ctx, key)` on non-existent key returns `ErrNotFound`.
- [ ] Re-run coverage: `go test -coverprofile=/tmp/aws.out ./internal/provider/aws/... && go tool cover -func=/tmp/aws.out | tail -1`. Target ≥ 95 %.

**Acceptance:** coverage on `internal/provider/aws` ≥ 95 %, error mapping table-driven test present, all assertions pass.

### Task 3.3 — CLI test coverage (76.2 → 95 %)

**Files:** extend `internal/cli/cli_test.go`, `internal/cli/cli_edge_test.go`.

- [ ] Test `skret init --force` overwrite path (after Task 2.6).
- [ ] Test `skret delete --force` skip-prompt path (after Task 2.6).
- [ ] Test `skret env --format=export` output (not currently covered).
- [ ] Test `skret list --values --confirm` (values included only with both flags).
- [ ] Test `skret list --recursive` with nested paths.
- [ ] Test `skret history KEY` returns experimental-gated error (after Task 3.1).
- [ ] Test `skret rollback KEY --to-version=N` returns experimental-gated error (after Task 3.1).
- [ ] Test all error exit codes (2 usage, 3 config, 4 auth, 5 not-found, 6 permission, 7 quota, 8 provider).
- [ ] Re-run coverage: target ≥ 95 %.

**Acceptance:** `internal/cli` coverage ≥ 95 %, every command's primary flag combinations hit at least one test path.

### Task 3.4 — Other internal packages

- [ ] `internal/exec` (82.6 → 95 %): Windows-path tests for env injection edge cases, signal forwarding (Ctrl+C → SIGINT propagation), exit code passthrough on non-zero child exits, PATH lookup failure.
- [ ] `internal/importer` (84.8 → 95 %): Doppler pagination over >100 secrets, Infisical machine-identity auth flow, dotenv multi-line value parsing, `--on-conflict=fail` abort path.
- [ ] `internal/provider/local` (80.3 → 95 %): concurrent write contention (acquire flock, write, release, verify serialization), atomic rename rollback when temp write fails midway, malformed YAML returns descriptive error.
- [ ] `internal/syncer` (81.7 → 95 %): GitHub public-key caching (second sync skips fetch), sealing with values containing newlines / high-bit bytes, dotenv escaping of backslashes / quotes / dollar-signs, >64KB secret rejection.

**Acceptance:** each package coverage ≥ 95 %, `go test -race ./...` green.

### Task 3.5 — `pkg/skret` tests (0 → 90 %)

**Files:** create `pkg/skret/client_test.go`, `pkg/skret/errors_test.go`.

- [ ] Drive `Client` end-to-end using the local provider (no mocks needed — `SecretProvider` interface is the same one used internally).
- [ ] Test `NewClient(ctx, ClientConfig)` success + common error paths.
- [ ] Test `Get`, `List`, `Set`, `Delete` on the client with a temp local YAML.
- [ ] Test context cancellation propagates through to provider calls.
- [ ] Test `errors.Is(err, skret.ErrNotFound)` on a missing key.
- [ ] Coverage target ≥ 90 %.

**Acceptance:** `go test -coverprofile=/tmp/pkg.out ./pkg/skret/...` reports ≥ 90 % on `pkg/skret`.

### Task 3.6 — Raise CI gate

**Files:** `.github/workflows/ci.yml`.

- [ ] Replace the `80` in `if (( $(echo "$COVERAGE < 80" | bc -l) )); then` with `95`.
- [ ] Add a second coverage step for `pkg/skret` with a 90 % gate.
- [ ] Add `govulncheck` job: `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...`.
- [ ] Add `gitleaks` job: use `gitleaks/gitleaks-action@v2`.
- [ ] Commit: `feat: raise coverage gate to 95 percent and add vuln scans`.

**Acceptance:** CI on a dummy PR shows both coverage gates and the two new scan jobs running; all pass on the current main.

### Task 3.7 — Amend v0.1 design spec §12.1

**Files:** `docs/superpowers/specs/2026-04-05-skret-cli-design.md`.

- [ ] Remove the `.infisical.json` line from the §12.1 required-files list.
- [ ] Add a short note below the list: `.infisical.json` intentionally omitted — skret bootstraps from environment variables only (see §14 Q4).
- [ ] Commit: `fix: drop .infisical.json from required files list`.

**Acceptance:** grep finds no `.infisical.json` reference in the v0.1 spec except the explanatory note.

---

## Phase 4 — Docs completeness

### Task 4.1 — Auto-generated reference

- [ ] Add a hidden `skret docs generate` subcommand (`internal/cli/docs.go`) that uses `cobra/doc.GenMarkdownTree(rootCmd, outputDir)` to emit one markdown file per command into `docs/commands/`.
- [ ] Add a Makefile / mise task `docs:generate` that runs `go run ./cmd/skret docs generate --out docs/commands`.
- [ ] Add a CI step that runs `docs:generate` and fails if there are uncommitted changes (ensures docs stay in sync with CLI).
- [ ] Commit: `feat: add docs generate subcommand for command reference`.

**Acceptance:** 9 files appear under `docs/commands/`, VitePress nav references them, CI drift check passes on a clean run.

### Task 4.2 — Guide pages

**Files:** create `docs/guide/authentication.md`, `docs/guide/troubleshooting.md`.

- [ ] `authentication.md`: cover AWS SDK credential chain, `AWS_PROFILE` vs `AWS_ROLE_ARN`, IMDSv2, GitHub Actions OIDC role trust policy sample, OCI IAM Roles Anywhere for VM workloads.
- [ ] `troubleshooting.md`: exit code table from design spec §7.1, common errors (`NoCredentialsFound`, `AccessDenied`, `ParameterNotFound`), `SKRET_LOG=DEBUG` usage, how to isolate whether the failure is skret or the provider.

**Acceptance:** both files exist, VitePress sidebar references them, content stays under 400 lines per file.

### Task 4.3 — Integrations

**Files:** create `docs/integrations/{github-actions,oci-vms,makefile-patterns,docker-compose}.md`.

- [ ] `github-actions.md`: OIDC role trust policy JSON, `permissions: id-token: write`, sync workflow template that calls `skret sync --to=github --from-env=prod`.
- [ ] `oci-vms.md`: IAM Roles Anywhere setup with step-ca, `~/.aws/credentials` process-credential configuration, `aws_process_credentials.sh` template.
- [ ] `makefile-patterns.md`: the exact replacements used in §7 of the hardening spec rollout — `make up-staging-<service>: skret run -- docker compose -f compose.staging.yml up -d` etc.
- [ ] `docker-compose.md`: `skret run -- docker compose up`, alternative `skret env > .env && docker compose up`, trade-offs.

**Acceptance:** all four files exist with working code samples, no placeholders.

### Task 4.4 — Cookbook

**Files:** create `docs/cookbook/{rotating-keys,multi-region-sync,team-access,backup-restore}.md`.

- [ ] `rotating-keys.md`: end-to-end rotation using `skret set --description "rotated on $(date +%F)"`, update-propagation via restart, verification.
- [ ] `multi-region-sync.md`: replicating an SSM path across two AWS regions using `skret list --values --confirm --region=ap-southeast-1 | while read; do skret set --region=us-east-1 ...; done`.
- [ ] `team-access.md`: IAM policy patterns for shared vs personal namespaces, code owner approvals on the consumer repo.
- [ ] `backup-restore.md`: `skret env --format=json > backup-$(date +%F).json`, encrypted S3 upload, restore via `skret import --from=dotenv`.

**Acceptance:** all four files exist, code samples reference real commands the CLI supports today.

### Task 4.5 — Reference

**Files:** create `docs/reference/{cli,config-schema,error-codes,library-api}.md`.

- [ ] `cli.md`: symlink / import from the auto-generated `commands/` index.
- [ ] `config-schema.md`: generate JSON schema from `internal/config/schema.go` types via `github.com/invopop/jsonschema`, embed into the markdown.
- [ ] `error-codes.md`: copy design spec §7.1 table verbatim, plus one-line remediation per row.
- [ ] `library-api.md`: link to `pkg.go.dev/github.com/n24q02m/skret/pkg/skret`, include a 10-line Go example of programmatic use.

**Acceptance:** all four files exist; the `go run ./cmd/skret docs schema > docs/reference/config-schema.md` pipeline works reproducibly.

### Task 4.6 — Contributing

**Files:** create `docs/contributing/{setup,adding-provider,adding-importer,release-process}.md`.

- [ ] `setup.md`: `mise install`, `pre-commit install`, `go mod download`, `make test`.
- [ ] `adding-provider.md`: interface checklist (`Name`, `Capabilities`, `Get`, `List`, `Set`, `Delete`, `Close`), registry registration, test doubles to add in `internal/provider/<name>_test.go`.
- [ ] `adding-importer.md`: similar checklist for `Importer` interface, auth token handling, pagination.
- [ ] `release-process.md`: how to cut a release (trigger `release.yml` via `workflow_dispatch`), CHANGELOG verification, how to promote beta → stable.

**Acceptance:** all four files exist, steps are concrete.

### Task 4.7 — FAQ + VitePress build

**Files:** create `docs/faq.md`, update `docs/.vitepress/config.ts`.

- [ ] `faq.md`: questions — `Why skret vs Doppler?`, `Why AWS SSM over Vault?`, `What does the free tier cover?`, `Does it work on Windows?`, `How do I migrate from Infisical self-host?`, `Can I use skret offline?`.
- [ ] Update VitePress nav/sidebar to include every new file from Tasks 4.1–4.6.
- [ ] Run `cd docs && pnpm install && pnpm build`. Fix any broken-link warnings.

**Acceptance:** `pnpm build` succeeds with zero broken-link warnings; generated `docs/.vitepress/dist/` contains every new page.

---

## Phase 5 — Integration testing with production repos

> **Gate:** user approves which repo enters Phase A / B / C at each step. Never proceed beyond Phase B on any repo without an observation window. See hardening spec §7.

### Task 5.1 — Phase A dry-run (17 repos)

For each repo in the order: knowledge-core → wet-mcp → better-code-review-graph → mnemo-mcp → mcp-relay-core → better-notion-mcp → better-email-mcp → better-telegram-mcp → better-godot-mcp → LinguaSense → oci-vm-infra → oci-vm-prod → web-core → virtual-company → QuikShipping → Aiora → KnowledgePrism:

- [ ] `cd <repo-local>` (clone if not present).
- [ ] Draft `.skret.yaml` at repo root covering every environment currently declared in Doppler / Infisical. Use `skret init --provider=aws --path=/<repo-slug>/<env>`.
- [ ] `skret import --from=doppler --doppler-project=<project> --doppler-config=<env> --to-path=/<repo-slug>/<env> --dry-run > tmp/migration/<repo>.txt`. For Infisical-backed repos use `--from=infisical` with the correct project id.
- [ ] Manually review `tmp/migration/<repo>.txt` for unexpected keys or missing keys.
- [ ] Record the final decision (proceed / fix / defer) in a per-repo row of `docs/superpowers/plans/2026-04-11-integration-matrix.md` (new file, created as part of this task).
- [ ] No writes to the consumer repo yet.

**Acceptance:** 17 per-repo rows in the integration matrix, each with a decision.

### Task 5.2 — Phase B staging adoption

Only for repos that passed Task 5.1 with `proceed`. In the same order:

- [ ] Real `skret import` (without `--dry-run`) into AWS SSM — verify the SSM paths contain all expected keys.
- [ ] Open a PR on the consumer repo: `feat(secrets): add skret run to staging targets` — edit only the staging `Makefile` / `justfile` target to replace `doppler run --` with `skret run --`.
- [ ] Run the staging target on the correct VM (`tailscale ssh ubuntu@infra-vnic` or `prod-vnic`), wait for health check.
- [ ] Observe for 48 h. Grep for errors in `/var/log/<service>` and in the service's centralized logs (Grafana / Loki).
- [ ] If the 48-h window is clean, mark the repo's Phase B row as `PASS` in `integration-matrix.md`. Otherwise `FAIL` + link to the error report.

**Acceptance:** each repo has a Phase B result recorded; no silent failures; any `FAIL` has an associated `fix:` PR on the skret repo.

### Task 5.3 — Phase C production cutover

Only for repos that passed Task 5.2 PASS. In the same order, 24 h apart:

- [ ] PR on consumer repo replacing prod target `doppler run --` → `skret run --`.
- [ ] Merge and roll out (trigger the repo's normal CD).
- [ ] Watch CloudTrail + CloudWatch logs + service health for 24 h.
- [ ] Mark Phase C result in `integration-matrix.md`.

**Acceptance:** 17 repos with Phase C PASS recorded. Zero service regressions attributed to skret across the 17-repo cutover window.

---

## Phase 6 — Release

### Task 6.1 — Seed CHANGELOG

- [ ] Run `python-semantic-release` locally in dry-run mode to generate what the CHANGELOG would look like against the current `main`:

  ```bash
  uv run --with python-semantic-release semantic-release version --print
  uv run --with python-semantic-release semantic-release changelog --post
  ```

- [ ] Inspect the generated content. If it's empty because commit types don't match `semantic-release.toml`, update `semantic-release.toml` to accept `fix:` and `feat:` only (and ignore the 3 pre-existing non-matching commits: `ci:`, `test(integration):`, `fix(test):`, `chore(repo):`).

  Actually rewrite strategy: amend those 4 commits on `main` via interactive rebase before semantic-release runs. Since `main` has no downstream forks, the rewrite is safe.

  ```bash
  git rebase -i ad5e552  # first skret commit
  # reword 2935e89 9a43be9 bc76f91 5820525 edea8b8 822420b 73a8597 8c702b9 780b3c0 4e1c4c6
  ```

  New subject lines (use `fix:` / `feat:` only):

  - `2935e89` `fix: resolve critical security/correctness issues and spec deviations from audit`
  - `9a43be9` `feat: add AWS SSM localstack/integration test skeleton`
  - `bc76f91` `feat: complete phase 4 with multi-os matrix codecov sbom cosign`
  - `5820525` `feat: configure repository standards and release ci`
  - `edea8b8` `feat: configure mcp-server standards`
  - `822420b` `feat: apply 17 prod standard structure`
  - `73a8597` `feat: synchronize readme and github setting rulesets`
  - `8c702b9` (duplicate of 73a8597 — drop if possible during rebase)
  - `780b3c0` `fix: localstack license and pass e2e tests`
  - `4e1c4c6` `feat: implement history rollback reference expansion and docs`

- [ ] Force-push `main` — **only if** no PR branches are currently based on the old commits. Verify with `git branch -r --contains <old-sha>`. If any remote branches are affected, rebase them too.

- [ ] Commit generated `CHANGELOG.md`: `feat: seed changelog with existing history`.

**Acceptance:** `CHANGELOG.md` has a non-empty `## [Unreleased]` section with entries matching the rebased commit subjects; all commits on `main` pass `grep -E '^(fix|feat)(\(.*\))?:' <(git log --format=%s)`.

### Task 6.2 — v0.0.1-alpha.1 dry-run tag

- [ ] `git tag v0.0.1-alpha.1 -m "alpha release for CD validation"`.
- [ ] `git push origin v0.0.1-alpha.1`.
- [ ] Watch `cd.yml` run: goreleaser → ghcr.io push → GitHub Release creation.
- [ ] Verify the release artifacts exist: 6 binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64), SHA256SUMS, SBOM files, cosign signatures.
- [ ] Pull the docker image and run: `docker pull ghcr.io/n24q02m/skret:v0.0.1-alpha.1 && docker run --rm ghcr.io/n24q02m/skret:v0.0.1-alpha.1 --version`. Verify the version string contains the alpha tag.

**Acceptance:** CD workflow green, all 6 binaries + Docker image published, `skret --version` reports `v0.0.1-alpha.1`.

### Task 6.3 — Fix CD findings

- [ ] For any CD step that failed in Task 6.2: create a `fix:` PR, merge, re-tag as `v0.0.1-alpha.2` (or higher), retry.
- [ ] Known risk: goreleaser ldflags paths must match `internal/version/version.go` variable names. Verify: `grep ldflags .goreleaser.yaml` and `grep var.*version internal/version/version.go` line up.

**Acceptance:** every CD step in the final alpha tag is green with no manual intervention.

### Task 6.4 — v0.1.0 release

- [ ] Trigger `release.yml` via `workflow_dispatch` with `release_type: stable`. python-semantic-release computes the next version from commit history; expect `v0.1.0` (first stable release).
- [ ] Watch CD run again.
- [ ] Once green, announce internally (Notion workspace, Telegram channel). Prepare a short blog draft in `docs/blog/2026-04-release-v0.1.0.md` (optional, not a success-criterion).

**Acceptance:** `v0.1.0` tag present, binaries + Docker image + GitHub release visible, CHANGELOG updated by semantic-release.

### Task 6.5 — Doppler / Infisical decommission

**Only** after every consumer repo has passed Phase C (Task 5.3) and 7 additional observation days elapsed.

- [ ] Export a final backup of all Doppler projects to encrypted JSONL (`doppler secrets --json | skret import --from=dotenv --dry-run > doppler-final-backup.jsonl.enc`).
- [ ] Snapshot the Infisical self-host disk (VM snapshot) and store the snapshot ID in the secrets manager of skret itself.
- [ ] Cancel the Doppler paid subscription.
- [ ] Stop the Infisical container on `infra-vnic` with `make down-infisical`. Do not delete the volume for 30 days in case of rollback.
- [ ] Record decommission date in `docs/superpowers/plans/2026-04-11-integration-matrix.md`.

**Acceptance:** Doppler dashboard billing = 0, Infisical container stopped, backups stored, rollback window documented.

---

## Manual gates

Per user rules `feedback_pr_review_process.md` and `feedback_check_original_requirements.md`, the following steps REQUIRE explicit user approval before execution:

| Gate | Step | What the user approves |
|------|------|-----------------------|
| G1 | Start of Phase 2 | The PR triage matrix in hardening spec §6.2 |
| G2 | Before Task 2.2 closing duplicate security PRs | Confirmation that #6 covers all the call sites |
| G3 | Before Task 3.1 | Whether to gate history/rollback or delete them |
| G4 | Before Task 5.2 on each repo | Per-repo staging adoption |
| G5 | Before Task 5.3 on each repo | Per-repo production cutover |
| G6 | Before Task 6.1 force-push | Rewriting main branch history |
| G7 | Before Task 6.4 | Tagging v0.1.0 stable |
| G8 | Before Task 6.5 | Cancelling Doppler + stopping Infisical |

---

## Rollback procedures

- **Phase 1** — each task is a single commit; revert by `git revert <sha>`.
- **Phase 2** — PR merges are squash commits; revert via `gh pr revert <n>` or `git revert -m 1 <merge-sha>`.
- **Phase 3** — coverage tests are additive; no rollback needed. Spec amendment (Task 3.7) reverted by `git revert`.
- **Phase 4** — docs are additive and independent; `git rm` the new files.
- **Phase 5** — per hardening spec §7.6: revert the consumer repo's Makefile, no destructive action on SSM.
- **Phase 6** — do not rollback a published tag. Instead, publish `v0.1.1` with the fix.

---

**End of plan.**
