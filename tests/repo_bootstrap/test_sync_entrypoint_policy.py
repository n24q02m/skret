import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "deploy" / "sync-entrypoint.sh"
DEPLOY_TEMPLATE = REPO_ROOT / "hub" / "wrangler.deploy.template.jsonc"
LOCAL_CONFIG = REPO_ROOT / "hub" / "wrangler.jsonc"


class SyncEntrypointPolicyTests(unittest.TestCase):
    def test_entrypoint_runs_config_free_planner_without_provider_inputs(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("exec /usr/local/bin/skret sync plan-server", script)
        self.assertIn("--listen 0.0.0.0:8080", script)
        self.assertIn("--max-body-bytes 1048576", script)
        self.assertNotIn("SKRET_HUB_TOKEN", script)
        self.assertNotIn("SKRET_HUB_URL", script)
        self.assertNotIn("/app/configs", script)
        self.assertNotIn("--config", script)

    def test_sync_image_is_config_free(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile.sync").read_text(encoding="utf-8")

        self.assertNotIn("COPY deploy/sync/", dockerfile)
        self.assertIn('COPY deploy/sync-entrypoint.sh /usr/local/bin/sync-entrypoint.sh', dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/sync-entrypoint.sh"]', dockerfile)
    def test_entrypoint_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["sh", "-n", str(ENTRYPOINT)],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deploy_configs_omit_unused_hub_url(self) -> None:
        for config_path in (DEPLOY_TEMPLATE, LOCAL_CONFIG):
            config = config_path.read_text(encoding="utf-8")
            self.assertNotIn('"SKRET_HUB_URL"', config, str(config_path))


if __name__ == "__main__":
    unittest.main()
