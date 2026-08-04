import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "repo-bootstrap" / "verify_readme_sync.py"


class VerifyReadmeSyncTests(unittest.TestCase):
    def run_gate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                f"--repo-root={root}",
                "--format=json",
            ],
            capture_output=True,
            encoding="utf-8",
            check=False,
        )

    def write_fixture(self, root: Path, dockerfile: str) -> None:
        (root / "README.md").write_text(
            "# Fixture\n\n**A portable secrets CLI for developers.**\n",
            encoding="utf-8",
        )
        (root / "Dockerfile").write_text(dockerfile, encoding="utf-8")

    def test_valid_readme_sync_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(
                root,
                'FROM alpine\nLABEL org.opencontainers.image.source="https://github.com/n24q02m/fixture"\n',
            )

            result = self.run_gate(root)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["summary"]["FAIL"], 0)

    def test_missing_oci_source_label_fails_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_fixture(root, "FROM alpine\n")

            result = self.run_gate(root)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            failed_checks = {
                item["name"] for item in payload["results"] if item["status"] == "FAIL"
            }
            self.assertIn("dockerfile_ghcr_label", failed_checks)


if __name__ == "__main__":
    unittest.main()
