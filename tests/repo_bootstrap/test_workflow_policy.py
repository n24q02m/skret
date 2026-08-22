import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LEGACY_OPENCODE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "opencode.yml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"


class WorkflowPolicyTests(unittest.TestCase):
    def test_cd_removes_direct_sync_job_and_preserves_deploy_jobs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        normalized = " ".join(workflow.split())

        for marker in (
            "sync-secrets:",
            "Sync Secrets from AWS SSM",
            "SYNC_SECRETS_ENABLED",
            "aws-actions/configure-aws-credentials",
            "./skret sync --to=github",
        ):
            self.assertNotIn(marker, normalized)
        release = workflow.split("\n  release:", 1)[1].split("\n  goreleaser:", 1)[0]
        self.assertIn("actions/create-github-app-token", release)
        self.assertIn("\n  docs-build:", workflow)
        self.assertIn("run: pnpm astro build", workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)
        self.assertIn("path: docs/dist", workflow)
        self.assertIn("retention-days: 7", workflow)
        for marker in (
            "command: pages deploy",
            "apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}",
            "Deploy Docs to Cloudflare Pages",
        ):
            self.assertNotIn(marker, workflow)
        self.assertIn("\n  deploy-hub:", workflow)

    def test_legacy_opencode_workflow_is_removed(self) -> None:
        self.assertFalse(LEGACY_OPENCODE_WORKFLOW.exists())

        tracked_workflows = subprocess.run(
            ["git", "ls-files", "--", ".github/workflows"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        for relative_path in tracked_workflows:
            workflow_path = REPO_ROOT / relative_path
            if not workflow_path.is_file():
                continue
            workflow = workflow_path.read_text(encoding="utf-8")
            for marker in (
                "anomalyco/opencode/github",
                "OPENCODE_CONFIG_CONTENT",
                "OC_PROXY_CONFIG",
            ):
                self.assertNotIn(marker, workflow, f"{marker} found in {relative_path}")


    def test_goreleaser_uses_pinned_binary_version(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        goreleaser = workflow.split("goreleaser/goreleaser-action", 1)[1].split(
            "        env:", 1
        )[0]
        self.assertIn("version: v2.17.1", goreleaser)
        self.assertNotIn("version: latest", goreleaser)

if __name__ == "__main__":
    unittest.main()
