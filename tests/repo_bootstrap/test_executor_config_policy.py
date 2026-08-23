import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_CONFIGS = (
    REPO_ROOT / "hub" / "wrangler.jsonc",
    REPO_ROOT / "hub" / "wrangler.deploy.template.jsonc",
)
EXECUTOR_CONFIG = REPO_ROOT / "hub" / "wrangler.executor.jsonc"
DEPLOYMENT_ORDER = REPO_ROOT / "hub" / "deployment-order.json"


def parse_jsonc(path: Path) -> dict:
    source = path.read_text(encoding="utf-8")
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if in_string:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            output.append(character)
            index += 1
            continue
        if character == "/" and following == "/":
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        output.append(character)
        index += 1
    return json.loads("".join(output))


class ExecutorConfigPolicyTests(unittest.TestCase):
    def test_hub_service_binding_matches_executor_worker_name(self) -> None:
        for path in HUB_CONFIGS:
            config = parse_jsonc(path)
            self.assertEqual(
                config["services"],
                [{"binding": "EXECUTOR", "service": "skret-security-executor"}],
                str(path),
            )

    def test_executor_is_not_publicly_exposed(self) -> None:
        config = parse_jsonc(EXECUTOR_CONFIG)
        self.assertFalse(config["workers_dev"])
        self.assertFalse(config["preview_urls"])
        self.assertNotIn("routes", config)

    def test_executor_sweep_trigger_is_bounded_and_configured(self) -> None:
        config = parse_jsonc(EXECUTOR_CONFIG)
        self.assertEqual(config["triggers"], {"crons": ["*/15 * * * *"]})

    def test_hub_readiness_requires_source_only_executor_deploy_order(self) -> None:
        order = json.loads(DEPLOYMENT_ORDER.read_text(encoding="utf-8"))
        self.assertEqual(
            order,
            {
                "executor_service": "skret-security-executor",
                "hub_worker": "skret-hub",
                "required_deploy_order": ["skret-security-executor", "skret-hub"],
                "executor_readback_required_before_hub_ready": True,
                "hub_ready_without_executor_readback": False,
                "hub_deploy_allowed": False,
                "hub_deploy_blocker": "executor_readback_required",
                "source_only": True,
            },
        )

    def test_executor_config_declares_replay_binding_and_migration(self) -> None:
        config = parse_jsonc(EXECUTOR_CONFIG)
        self.assertEqual(config["name"], "skret-security-executor")
        self.assertEqual(config["main"], "src/security-executor.ts")
        self.assertEqual(
            config["durable_objects"]["bindings"],
            [{"name": "EXECUTOR_REPLAY", "class_name": "SecurityExecutorReplay"}],
        )
        self.assertEqual(
            config["migrations"],
            [{"tag": "v1", "new_sqlite_classes": ["SecurityExecutorReplay"]}],
        )
        self.assertEqual(
            config["vars"],
            {
                "EXECUTOR_EXPECTED_AUDIENCE": "skret-security-executor",
                "EXECUTOR_EXPECTED_ROLE": "operator",
            },
        )
        self.assertNotIn("EXECUTOR_PUBLIC_KEY", config)
        self.assertNotIn("EXECUTOR_STATE_MANIFEST_PUBLIC_KEY", config)
        self.assertNotIn("EXECUTOR_RESPONSE_KEY", config)


if __name__ == "__main__":
    unittest.main()
