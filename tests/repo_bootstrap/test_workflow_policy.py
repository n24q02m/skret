import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
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
        self.assertIn("\n  docs:", workflow)
        self.assertIn("\n  deploy-hub:", workflow)


if __name__ == "__main__":
    unittest.main()
