from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "home_sandbox.py"
SENTINEL = "synthetic-home-canary-value"


def load_module():
    spec = importlib.util.spec_from_file_location("home_sandbox", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Home sandbox module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


home = load_module()


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_signed_state_manifest(
    state_root: Path,
    state: Path,
    manifest_path: Path,
    public_key_path: Path,
    expires_at: datetime,
) -> dict[str, object]:
    trust = home._candidate_trust_module()
    private_key, public_key = trust.generate_keypair(seed=b"\x07" * 32)
    signing_document = {
        "version": 1,
        "role": "operator",
        "audience": "hub",
        "source_root": str(state_root),
        "files": [
            {
                "path": state.relative_to(state_root).as_posix(),
                "size": state.stat().st_size,
                "sha256": digest(state).removeprefix("sha256:"),
            }
        ],
        "nonce": "home-sandbox-test",
        "expires_at": expires_at.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    manifest = dict(signing_document)
    manifest["signature"] = base64.b64encode(
        trust.sign_bytes(home._go_json_bytes(signing_document), private_key)
    ).decode("ascii")
    manifest_path.write_bytes(home._go_json_bytes(manifest))
    public_key_path.write_bytes(public_key)
    return manifest


class FakeRunner:
    def __init__(self, *, fail_at: str | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, str], str]] = []
        self.fail_at = fail_at

    def run(self, argv: list[str], env: dict[str, str], cwd: str):
        self.calls.append((list(argv), dict(env), cwd))
        operation = "version" if "--version" in argv else next(
            (name for name in ("list", "sync", "run", "sync-state") if name in argv),
            "unknown",
        )
        if operation == self.fail_at:
            return home.CommandResult(9, b"", b"synthetic failure")
        if operation == "version":
            return home.CommandResult(0, b"skret 1.2.3-beta.1\n", b"")
        if operation == "list":
            return home.CommandResult(0, b'[{"key":"SYNTHETIC_CANARY"}]\n', b"")
        return home.CommandResult(0, b'{"ok":true}\n', b"")


class MutatingMigrationRunner(FakeRunner):
    def run(self, argv: list[str], env: dict[str, str], cwd: str):
        result = super().run(argv, env, cwd)
        if result.returncode == 0 and "sync-state" in argv and "--execute" in argv:
            state_path = Path(argv[argv.index("--state") + 1])
            state_path.write_bytes(b'{"schema_version":2}')
        return result


class CapturingMigrationRunner(FakeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.manifests: list[dict[str, object]] = []

    def run(self, argv: list[str], env: dict[str, str], cwd: str):
        if "sync-state" in argv:
            manifest_path = Path(argv[argv.index("--state-manifest") + 1])
            self.manifests.append(json.loads(manifest_path.read_text(encoding="utf-8")))
        return super().run(argv, env, cwd)


class HomeSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.live_binary = self.root / "live-skret.exe"
        self.live_binary.write_bytes(b"stable-binary")
        self.live_config = self.root / "live.skret.yaml"
        self.live_config.write_bytes(b"live-config-metadata-only")
        self.candidate = self.root / "candidate-skret.exe"
        self.candidate.write_bytes(b"candidate-binary")
        self.synthetic_config = self.root / "synthetic.skret.yaml"
        self.synthetic_config.write_text(
            'version: "1"\ndefault_env: candidate\nenvironments:\n  candidate:\n    provider: local\n    file: synthetic-values.yaml\n',
            encoding="utf-8",
        )
        self.synthetic_values = self.root / "synthetic-values.yaml"
        self.synthetic_values.write_text(
            f'version: "1"\nsecrets:\n  SYNTHETIC_CANARY: "{SENTINEL}"\n',
            encoding="utf-8",
        )
        self.sentinel_program = self.root / "sentinel-check.exe"
        self.sentinel_program.write_bytes(b"synthetic-sentinel-program")
        self.state_root = self.root / "synthetic-state-root"
        self.state_root.mkdir()
        self.state = self.state_root / "state.v1.json"
        self.state.write_bytes(b'{"schema_version":1}')
        self.sandbox = self.root / "sandbox"
        self.staged_state_root = self.sandbox / "synthetic-state"
        self.state_manifest = self.state_root / "state-manifest.json"
        self.state_public_key = self.state_root / "state-public-key"
        write_signed_state_manifest(
            self.state_root,
            self.state,
            self.state_manifest,
            self.state_public_key,
            datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        self.spec = {
            "schema": "skret-home-sandbox/v1",
            "candidate_binary": str(self.candidate),
            "candidate_digest": digest(self.candidate),
            "candidate_version": "1.2.3-beta.1",
            "live_binary": str(self.live_binary),
            "live_config_paths": [str(self.live_config)],
            "synthetic_config": str(self.synthetic_config),
            "synthetic_values": str(self.synthetic_values),
            "sentinel_program": str(self.sentinel_program),
            "synthetic_state_root": str(self.state_root),
            "state_file": str(self.state),
            "state_manifest": str(self.state_manifest),
            "state_public_key": str(self.state_public_key),
            "sandbox_root": str(self.sandbox),
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_candidate_runs_names_only_dry_run_child_and_synthetic_state_migration(self) -> None:
        runner = FakeRunner()
        result = home.run_sandbox(self.spec, runner)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["candidate_digest"], self.spec["candidate_digest"])
        self.assertEqual(result["rollback_digest"], digest(self.live_binary))
        self.assertEqual(result["live_before"], result["live_after"])
        self.assertEqual(result["synthetic_state_before"], result["synthetic_state_after"])
        self.assertFalse(Path(self.spec["sandbox_root"]).exists())
        encoded = home.canonical_json_bytes(result).decode("utf-8")
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("synthetic-values.yaml", encoded)

        commands = [call[0] for call in runner.calls]
        self.assertEqual(len(commands), 7)
        self.assertTrue(any("--version" in command for command in commands))
        list_command = next(command for command in commands if "list" in command)
        self.assertNotIn("--values", list_command)
        sync_command = next(command for command in commands if "sync" in command and "sync-state" not in command)
        self.assertIn("--dry-run", sync_command)
        run_command = next(command for command in commands if "run" in command)
        self.assertIn("--", run_command)
        migration_commands = [command for command in commands if "sync-state" in command]
        self.assertEqual(len(migration_commands), 2)
        self.assertNotIn("--execute", migration_commands[0])
        self.assertIn("--execute", migration_commands[1])
        for command in migration_commands:
            self.assertIn("--role", command)
            self.assertIn("--audience", command)
            self.assertIn("--operation-id", command)
            self.assertEqual(command[command.index("--role") + 1], "operator")
            self.assertEqual(command[command.index("--audience") + 1], "hub")
            self.assertEqual(command[command.index("--operation-id") + 1], "home-sandbox-local")
            self.assertEqual(Path(command[command.index("--state") + 1]), self.staged_state_root / "state.v1.json")
            self.assertEqual(Path(command[command.index("--state-manifest") + 1]), self.staged_state_root / "state-manifest.json")
            self.assertEqual(Path(command[command.index("--public-key") + 1]), self.staged_state_root / "state-public-key")
        for command, environment, cwd in runner.calls:
            self.assertNotIn("env", command)
            self.assertNotIn("AWS_ACCESS_KEY_ID", environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
            self.assertEqual(Path(cwd), Path(self.spec["sandbox_root"]))
            self.assertEqual(Path(environment["HOME"]), Path(self.spec["sandbox_root"]) / "home")
            self.assertEqual(Path(environment["USERPROFILE"]), Path(self.spec["sandbox_root"]) / "home")

    def test_execute_migrates_only_staged_state_and_preserves_external_root(self) -> None:
        external_paths = [self.state, self.state_manifest, self.state_public_key]
        before = {path.name: digest(path) for path in external_paths}

        result = home.run_sandbox(self.spec, MutatingMigrationRunner())

        after = {path.name: digest(path) for path in external_paths}
        self.assertEqual(after, before)
        self.assertEqual(result["synthetic_state_before"], result["synthetic_state_after"])
        self.assertFalse(Path(self.spec["sandbox_root"]).exists())

    def test_staged_manifest_never_outlives_source_authority(self) -> None:
        source = write_signed_state_manifest(
            self.state_root,
            self.state,
            self.state_manifest,
            self.state_public_key,
            datetime.now(timezone.utc) + timedelta(seconds=30),
        )
        runner = CapturingMigrationRunner()

        result = home.run_sandbox(self.spec, runner)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(runner.manifests), 2)
        for staged in runner.manifests:
            self.assertEqual(staged["expires_at"], source["expires_at"])
            self.assertEqual(Path(str(staged["source_root"])), self.staged_state_root)

    @unittest.skipUnless(os.name == "nt", "Windows subprocess contract")
    def test_subprocess_runner_forwards_required_local_migration_flags(self) -> None:
        candidate = self.root / "candidate.cmd"
        live_binary = self.root / "live.cmd"
        command = """@echo off
if /I "%~1"=="--version" (
  echo skret 1.2.3-beta.1
  exit /b 0
)
if /I "%~1"=="list" (
  echo [{"key":"SYNTHETIC_CANARY"}]
  exit /b 0
)
if /I "%~1"=="sync-state" (
  echo %* | findstr /C:"--role operator" >nul || exit /b 21
  echo %* | findstr /C:"--audience hub" >nul || exit /b 22
  echo %* | findstr /C:"--operation-id home-sandbox-local" >nul || exit /b 23
  echo {"ok":true}
  exit /b 0
)
echo {"ok":true}
exit /b 0
"""
        candidate.write_text(command, encoding="utf-8")
        live_binary.write_text(command, encoding="utf-8")
        subprocess_sandbox = self.root / "subprocess-sandbox"
        spec = dict(self.spec)
        spec.update(
            candidate_binary=str(candidate),
            candidate_digest=digest(candidate),
            live_binary=str(live_binary),
            sentinel_program=str(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"),
            sandbox_root=str(subprocess_sandbox),
        )

        result = home.run_sandbox(spec)

        self.assertEqual(result["status"], "passed")
        self.assertFalse(Path(spec["sandbox_root"]).exists())

    def test_failure_cleans_sandbox_and_preserves_every_live_hash(self) -> None:
        before = {path: digest(Path(path)) for path in [self.spec["live_binary"], *self.spec["live_config_paths"]]}
        runner = FakeRunner(fail_at="list")
        with self.assertRaises(home.HomeSandboxError):
            home.run_sandbox(self.spec, runner)
        after = {path: digest(Path(path)) for path in before}
        self.assertEqual(after, before)
        self.assertFalse(Path(self.spec["sandbox_root"]).exists())

    def test_state_manifest_must_bind_the_external_synthetic_state_root(self) -> None:
        manifest = json.loads(self.state_manifest.read_text(encoding="utf-8"))
        manifest["source_root"] = str(self.staged_state_root)
        self.state_manifest.write_bytes(home._go_json_bytes(manifest))
        runner = FakeRunner()
        with self.assertRaises(home.HomeSandboxError):
            home.run_sandbox(self.spec, runner)
        self.assertEqual(runner.calls, [])

    def test_dot_segment_state_path_cannot_escape_the_sandbox(self) -> None:
        outside_source = self.root.parent / f"{self.root.name}-outside-state.json"
        outside_source.write_bytes(b'{"schema_version":1}')
        self.addCleanup(lambda: outside_source.unlink(missing_ok=True))
        traversal = self.state_root / "nested" / ".." / ".." / ".." / outside_source.name
        escaped_destination = self.root / outside_source.name
        wrong = dict(self.spec)
        wrong["state_file"] = str(traversal)
        runner = FakeRunner()
        with self.assertRaises(home.HomeSandboxError):
            home.run_sandbox(wrong, runner)

        self.assertEqual(runner.calls, [])
        self.assertFalse(escaped_destination.exists())
        self.assertFalse(Path(self.spec["sandbox_root"]).exists())

    def test_digest_path_overlap_and_noncanonical_specs_fail_before_execution(self) -> None:
        runner = FakeRunner()
        wrong = dict(self.spec)
        wrong["candidate_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(home.HomeSandboxError):
            home.run_sandbox(wrong, runner)
        self.assertEqual(runner.calls, [])

        overlap = dict(self.spec)
        overlap["sandbox_root"] = str(self.live_binary)
        with self.assertRaises(home.HomeSandboxError):
            home.run_sandbox(overlap, runner)
        self.assertEqual(runner.calls, [])

        canonical = home.canonical_json_bytes(self.spec)
        self.assertEqual(home.parse_spec(canonical), self.spec)
        with self.assertRaises(home.HomeSandboxError):
            home.parse_spec(b" " + canonical)
        with self.assertRaises(home.HomeSandboxError):
            home.parse_spec(canonical[:-1] + b',"schema":"duplicate"}')


if __name__ == "__main__":
    unittest.main()
