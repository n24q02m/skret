import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_CONFIGS = (
    REPO_ROOT / "hub" / "wrangler.jsonc",
    REPO_ROOT / "hub" / "wrangler.deploy.template.jsonc",
)
EXECUTOR_CONFIG = REPO_ROOT / "hub" / "wrangler.executor.jsonc"


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
        self.assertNotIn("EXECUTOR_RESPONSE_KEY", config)


if __name__ == "__main__":
    unittest.main()
