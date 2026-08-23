import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "deploy" / "sync-entrypoint.sh"
DEPLOY_TEMPLATE = REPO_ROOT / "hub" / "wrangler.deploy.template.jsonc"
LOCAL_CONFIG = REPO_ROOT / "hub" / "wrangler.jsonc"


class SyncEntrypointPolicyTests(unittest.TestCase):
    def test_entrypoint_rejects_missing_hub_configuration_before_provider_sync(self) -> None:
        script = ENTRYPOINT.read_text(encoding="utf-8")
        sync_call = script.index("skret sync")

        self.assertIn('case "${SKRET_HUB_TOKEN:-}" in', script[:sync_call])
        self.assertIn('case "${SKRET_HUB_URL:-}" in', script[:sync_call])
        self.assertIn("missing required SKRET_HUB_TOKEN", script[:sync_call])
        self.assertIn("missing required SKRET_HUB_URL", script[:sync_call])
        self.assertNotIn('echo "${SKRET_HUB_TOKEN}', script)
        self.assertNotIn('echo "${SKRET_HUB_URL}', script)

    def test_entrypoint_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["sh", "-n", str(ENTRYPOINT)],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deploy_configs_provide_runtime_hub_url(self) -> None:
        for config_path in (DEPLOY_TEMPLATE, LOCAL_CONFIG):
            config = config_path.read_text(encoding="utf-8")
            self.assertIn(
                '"SKRET_HUB_URL": "https://vault.n24q02m.com"',
                config,
                str(config_path),
            )


if __name__ == "__main__":
    unittest.main()
