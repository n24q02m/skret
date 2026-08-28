import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_executor_readback.py"
READBACK_ENV = "SKRET_EXECUTOR_READBACK_JSON"


class ExecutorReadbackPolicyTests(unittest.TestCase):
    def run_guard(self, raw: str | None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop(READBACK_ENV, None)
        if raw is not None:
            env[READBACK_ENV] = raw
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def valid_readback(self, **overrides: object) -> str:
        payload: dict[str, object] = {
            "executor_service": "skret-security-executor",
            "hub_worker": "skret-hub",
            "binding": "EXECUTOR",
            "ready": True,
            "readback": "verified",
            "hub_deploy_allowed": True,
        }
        payload.update(overrides)
        return json.dumps(payload)

    def test_missing_or_malformed_readback_fails_without_values(self) -> None:
        for raw in (None, "{not-json", json.dumps({"ready": True})):
            result = self.run_guard(raw)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("skret-security-executor", result.stdout + result.stderr)
            self.assertNotIn("SKRET_EXECUTOR_READBACK_JSON", result.stdout + result.stderr)

    def test_false_or_mismatched_readback_fails_closed(self) -> None:
        cases = (
            {"ready": False},
            {"hub_deploy_allowed": False},
            {"readback": "pending"},
            {"executor_service": "other-worker"},
            {"hub_worker": "other-hub"},
            {"binding": "OTHER"},
        )
        for override in cases:
            result = self.run_guard(self.valid_readback(**override))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("other-worker", result.stdout + result.stderr)
            self.assertNotIn("other-hub", result.stdout + result.stderr)

    def test_verified_readback_allows_hub_deploy_without_printing_payload(self) -> None:
        secret = "synthetic-readback-detail"
        result = self.run_guard(self.valid_readback(detail=secret))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "executor readback verified")
        self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
