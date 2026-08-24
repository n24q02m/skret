import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOW_DIR / "ci.yml"
CD_WORKFLOW = WORKFLOW_DIR / "cd.yml"
HUB_DIR = REPO_ROOT / "hub"
EXPECTED_WORKFLOWS = {"ci.yml", "cd.yml"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkflowPolicyTests(unittest.TestCase):
    def _workflow_sources(self) -> list[Path]:
        return sorted(
            path
            for path in WORKFLOW_DIR.iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        )

    def test_final_workflow_set_is_exactly_ci_and_cd(self) -> None:
        self.assertEqual(
            {path.name for path in self._workflow_sources()}, EXPECTED_WORKFLOWS
        )
        self.assertTrue(CI_WORKFLOW.is_file())
        self.assertTrue(CD_WORKFLOW.is_file())

    def test_every_workflow_action_is_full_sha_pinned(self) -> None:
        for path in self._workflow_sources():
            source = path.read_text(encoding="utf-8")
            for line_number, line in enumerate(source.splitlines(), start=1):
                if not re.match(r"^\s*-\s+uses:\s*", line):
                    continue
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                self.assertIn("@", reference, f"missing action pin at {path}:{line_number}")
                self.assertTrue(
                    FULL_SHA.fullmatch(reference.rsplit("@", 1)[1]),
                    f"non-SHA action pin at {path}:{line_number}: {reference}",
                )

    def test_ci_merges_scorecard_and_codeql_security_checks(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "branch_protection_rule:",
            'cron: "0 3 * * 1"',
            "scorecard:",
            "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc",
            "if: github.event_name != 'pull_request'",
            "publish_results: true",
            "codeql:",
            "language: [go, javascript-typescript]",
            "github/codeql-action/init@5595ccaf912efad79be6eef63a5619ff05969be3",
            "github/codeql-action/autobuild@5595ccaf912efad79be6eef63a5619ff05969be3",
            "github/codeql-action/analyze@5595ccaf912efad79be6eef63a5619ff05969be3",
            "upload: never",
        ):
            self.assertIn(marker, workflow)
        self.assertGreaterEqual(workflow.count("github/codeql-action/init@"), 1)
        self.assertGreaterEqual(workflow.count("github/codeql-action/autobuild@"), 1)
        self.assertGreaterEqual(workflow.count("github/codeql-action/analyze@"), 1)
        for existing_job in (
            "repo-bootstrap-verify:",
            "pr-title:",
            "lint:",
            "test:",
            "build:",
            "installer-lint:",
            "installer-smoke:",
            "dependency-review:",
            "docs-build:",
            "hub:",
        ):
            self.assertIn(f"\n  {existing_job}", workflow)

    def test_cd_is_prepare_only_with_non_cancelling_concurrency(self) -> None:
        workflow = CD_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("group: skret-release-prepare", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("\n  prepare:", workflow)
        for forbidden_job in (
            "release:",
            "goreleaser:",
            "deploy-hub:",
            "publish:",
            "sign:",
            "channel-publish:",
        ):
            self.assertNotIn(f"\n  {forbidden_job}", workflow)

    def test_cd_preserves_candidate_outputs_and_exact_prepare_command(self) -> None:
        workflow = CD_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "n24q02m/better-semantic-release@2335089f3744c77ca7ef389493a87e0cc117cc2a",
            "no_operation_mode: true",
            "github_token: ${{ github.token }}",
            "config_file: semantic-release.toml",
            "commit: false",
            "tag: false",
            "push: false",
            "vcs_release: false",
            "build: false",
            "steps.release.outputs.version",
            "steps.release.outputs.tag",
            'git tag --no-sign "$CANDIDATE_TAG" "$SOURCE_SHA"',
            "args: release --clean --skip=publish -f .goreleaser.prepare.yaml",
            "version: v2.17.1",
        ):
            self.assertIn(marker, workflow)

    def test_cd_emits_all_prepared_artifact_families(self) -> None:
        workflow = CD_WORKFLOW.read_text(encoding="utf-8")
        for artifact_name in (
            "name: cli",
            "name: archives",
            "name: checksums",
            "name: sbom",
            "name: cli-oci",
            "name: sync-oci",
            "name: hub",
            "name: security-executor",
            "name: docs",
            "name: release-journal",
        ):
            self.assertIn(artifact_name, workflow)
        for artifact_path in (
            "dist/skret-cli.oci.tar",
            "dist/skret-sync.oci.tar",
            "dist/hub.bundle.tar",
            "dist/security-executor.bundle.tar",
            "dist/docs.bundle.tar",
            "dist/skret-secret-helper_*/skret-secret-helper",
            "dist/skret-compose-supervisor_*/skret-compose-supervisor",
            "dist/CHANGELOG.md",
            "dist/artifacts.json",
            "dist/config.yaml",
            "dist/metadata.json",
            "dist/auxiliary-checksums.txt",
            "dist/artifact-manifest.sha256",
            "dist/source-manifest.sha256",
            "dist/*.sbom.json",
        ):
            self.assertIn(artifact_path, workflow)
        self.assertIn("tar -xOf \"$amd64_archive\" skret", workflow)
        self.assertIn("tar -xOf \"$arm64_archive\" skret", workflow)
        self.assertIn("--output type=oci,dest=dist/skret-sync.oci.tar", workflow)
        self.assertIn("syft \"oci-archive:dist/skret-sync.oci.tar\"", workflow)

    def test_cd_initializes_value_free_release_journal(self) -> None:
        workflow = CD_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "python scripts/release_transaction.py init",
            "--journal \"$RUNNER_TEMP/release-journal.jsonl\"",
            "--transaction-id \"$transaction_id\"",
            "--channel \"$JOURNAL_CHANNEL\"",
            "--source-sha \"$SOURCE_SHA\"",
            "--artifact-digest \"$artifact_digest\"",
            "--intent-digest \"$intent_digest\"",
            "--timestamp \"$timestamp\"",
        ):
            self.assertIn(marker, workflow)
        self.assertIn("sha256:$(sha256sum", workflow)
        self.assertIn('transaction_id="cd-${GITHUB_RUN_ID}"', workflow)
        self.assertNotIn("GITHUB_RUN_ATTEMPT", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_cd_has_read_only_permissions_and_no_mutation_credentials(self) -> None:
        workflow = CD_WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "contents: write",
            "packages: write",
            "id-token: write",
            "pull-requests: write",
            "actions/create-github-app-token",
            "CI_APP_KEY",
            "TAP_GITHUB_TOKEN",
            "CLOUDFLARE_",
            "AWS_ACCESS_KEY",
            "AWS_SECRET",
            "AWS_ROLE_ARN",
            "docker/login-action",
            "docker push",
            "wrangler containers push",
            "wrangler-action",
            "semantic-release/publish-action",
            "cosign",
            "apiToken:",
            "command: deploy",
            "command: pages deploy",
        ):
            self.assertNotIn(marker, workflow)
        for line in workflow.splitlines():
            if "wrangler deploy" in line:
                self.assertIn("--dry-run", line)
        self.assertIn("pnpm test", workflow)
        self.assertIn("pnpm typecheck", workflow)

    def test_hub_public_surface_is_build_only(self) -> None:
        package = json.loads((HUB_DIR / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(
            set(package["scripts"]), {"test", "test:watch", "typecheck", "dryrun"}
        )
        self.assertIn("--dry-run", package["scripts"]["dryrun"])

        readme = (HUB_DIR / "README.md").read_text(encoding="utf-8")
        for line in readme.splitlines():
            if "wrangler deploy" in line:
                self.assertIn("--dry-run", line)
        for marker in (
            "wrangler containers push",
            "wrangler secret",
            "curl -X PUT",
            "HUB_CF_DEPLOY_TOKEN",
            "CLOUDFLARE_API_TOKEN",
        ):
            self.assertNotIn(marker, readme)

        for path in HUB_DIR.glob("wrangler*.jsonc"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("wrangler containers push", source)
            self.assertNotRegex(source, r"wrangler\s+secret\s+")
            self.assertNotRegex(source, r"curl\s+-X\s+(?:PUT|POST|DELETE)")

    def test_no_legacy_mutating_workflow_markers_remain_anywhere(self) -> None:
        for path in self._workflow_sources():
            source = path.read_text(encoding="utf-8")
            for marker in (
                "anomalyco/opencode/github",
                "OPENCODE_CONFIG_CONTENT",
                "OC_PROXY_CONFIG",
                "sync-secrets:",
                "SYNC_SECRETS_ENABLED",
                "aws-actions/configure-aws-credentials",
                "./skret sync --to=github",
            ):
                self.assertNotIn(marker, source, f"{marker} found in {path.name}")


if __name__ == "__main__":
    unittest.main()
