from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "oci_arm64_harness.py"
VERSION = "1.2.3-beta.1"
SOURCE_SHA = "a" * 40
REQUIRED_SCENARIOS = [
    "archive-load",
    "daemon-restart",
    "names-only",
    "orphan-scavenge",
    "rollback",
    "secret-helper",
    "sentinel-child",
    "supervisor-crash",
    "sync-dry-run",
]


def load_module():
    spec = importlib.util.spec_from_file_location("oci_arm64_harness", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load OCI ARM64 harness module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


arm64 = load_module()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_oci_archive(path: Path, entrypoint: list[str], *, secret_env: bool = False, platform: str = "arm64") -> None:
    config = {
        "architecture": platform,
        "os": "linux",
        "config": {
            "Entrypoint": entrypoint,
            "Cmd": ["--version"],
            "Env": ["PATH=/usr/local/bin:/usr/bin"] + (["API_TOKEN=must-not-appear"] if secret_env else []),
            "Labels": {
                "org.opencontainers.image.revision": SOURCE_SHA,
                "org.opencontainers.image.version": VERSION,
            },
        },
        "rootfs": {"type": "layers", "diff_ids": []},
        "history": [],
    }
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    config_digest = sha(config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:" + config_digest,
            "size": len(config_bytes),
        },
        "layers": [],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_digest = sha(manifest_bytes)
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + manifest_digest,
                "size": len(manifest_bytes),
                "platform": {"architecture": platform, "os": "linux"},
            }
        ],
    }
    members = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps(index, sort_keys=True, separators=(",", ":")).encode(),
        f"blobs/sha256/{manifest_digest}": manifest_bytes,
        f"blobs/sha256/{config_digest}": config_bytes,
    }
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class FakeArm64Runner:
    def __init__(self, *, failed: str | None = None) -> None:
        self.failed = failed
        self.calls = 0

    def run(self, request):
        self.calls += 1
        return [
            arm64.ScenarioResult(
                name=name,
                status="failed" if name == self.failed else "passed",
                evidence_digest="sha256:" + hashlib.sha256(name.encode()).hexdigest(),
                persistent_matches=0,
            )
            for name in REQUIRED_SCENARIOS
        ]


class OCIArm64HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cli_archive = self.root / "skret-cli.oci.tar"
        self.sync_archive = self.root / "skret-sync.oci.tar"
        create_oci_archive(self.cli_archive, ["/usr/local/bin/skret"])
        create_oci_archive(self.sync_archive, ["/usr/local/bin/sync-entrypoint.sh"])
        self.launch_manifest = self.root / "launch-manifest.json"
        self.launch_manifest.write_bytes(b'{"schema":"skret-secret-launch/v1"}')
        self.live_binary = self.root / "live-skret"
        self.live_binary.write_bytes(b"stable-live-binary")
        self.live_config = self.root / "live-config"
        self.live_config.write_bytes(b"stable-live-config")
        self.spec = {
            "schema": "skret-oci-arm64-harness/v1",
            "candidate_version": VERSION,

            "source_sha": SOURCE_SHA,
            "cli_archive": str(self.cli_archive),
            "cli_archive_digest": file_digest(self.cli_archive),
            "cli_entrypoint": ["/usr/local/bin/skret"],
            "sync_archive": str(self.sync_archive),
            "sync_archive_digest": file_digest(self.sync_archive),
            "sync_entrypoint": ["/usr/local/bin/sync-entrypoint.sh"],
            "launch_manifest": str(self.launch_manifest),
            "launch_manifest_digest": file_digest(self.launch_manifest),
            "live_paths": sorted([str(self.live_binary), str(self.live_config)]),
            "platform": "linux/arm64",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()
    def test_source_image_entrypoints_are_absolute_and_config_free(self) -> None:
        cli_dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        sync_dockerfile = (REPO_ROOT / "Dockerfile.sync").read_text(encoding="utf-8")
        sync_entrypoint = (REPO_ROOT / "deploy" / "sync-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('ENTRYPOINT ["/usr/local/bin/skret"]', cli_dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/sync-entrypoint.sh"]', sync_dockerfile)
        self.assertIn("skret sync plan-server", sync_entrypoint)
        self.assertNotIn("deploy/sync/", sync_dockerfile)


    def test_exact_arm64_archives_and_all_isolated_scenarios_pass_without_live_mutation(self) -> None:
        runner = FakeArm64Runner()
        result = arm64.run_harness(self.spec, runner)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["platform"], "linux/arm64")
        self.assertEqual([row["name"] for row in result["scenarios"]], REQUIRED_SCENARIOS)
        self.assertEqual(result["live_before"], result["live_after"])
        self.assertEqual(runner.calls, 1)
        encoded = arm64.canonical_json_bytes(result).decode()
        self.assertNotIn("must-not-appear", encoded)
        self.assertNotIn(str(self.live_binary), encoded)

    def test_wrong_digest_platform_secret_env_and_unsafe_tar_fail_before_runtime(self) -> None:
        cases = []
        wrong_digest = dict(self.spec)
        wrong_digest["cli_archive_digest"] = "sha256:" + "0" * 64
        cases.append(wrong_digest)

        wrong_platform_archive = self.root / "wrong-platform.tar"
        create_oci_archive(wrong_platform_archive, ["/usr/local/bin/skret"], platform="amd64")
        wrong_platform = dict(self.spec)
        wrong_platform["cli_archive"] = str(wrong_platform_archive)
        wrong_platform["cli_archive_digest"] = file_digest(wrong_platform_archive)
        cases.append(wrong_platform)

        secret_archive = self.root / "secret-env.tar"
        create_oci_archive(secret_archive, ["/usr/local/bin/skret"], secret_env=True)
        secret_env = dict(self.spec)
        secret_env["cli_archive"] = str(secret_archive)
        secret_env["cli_archive_digest"] = file_digest(secret_archive)
        cases.append(secret_env)

        unsafe_archive = self.root / "unsafe.tar"
        extra_archive = self.root / "extra.tar"
        create_oci_archive(extra_archive, ["/usr/local/bin/skret"])
        with tarfile.open(extra_archive, "a") as archive:
            info = tarfile.TarInfo("unbound-extra.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        extra = dict(self.spec)
        extra["cli_archive"] = str(extra_archive)
        extra["cli_archive_digest"] = file_digest(extra_archive)
        cases.append(extra)

        with tarfile.open(unsafe_archive, "w") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        unsafe = dict(self.spec)
        unsafe["cli_archive"] = str(unsafe_archive)
        unsafe["cli_archive_digest"] = file_digest(unsafe_archive)
        cases.append(unsafe)

        for spec in cases:
            runner = FakeArm64Runner()
            with self.assertRaises(arm64.OCIArm64HarnessError):
                arm64.run_harness(spec, runner)
            self.assertEqual(runner.calls, 0)

    def test_failed_or_incomplete_scenario_matrix_fails_and_preserves_live_hashes(self) -> None:
        before = [file_digest(Path(path)) for path in self.spec["live_paths"]]
        with self.assertRaises(arm64.OCIArm64HarnessError):
            arm64.run_harness(self.spec, FakeArm64Runner(failed="daemon-restart"))
        self.assertEqual([file_digest(Path(path)) for path in self.spec["live_paths"]], before)

        class IncompleteRunner:
            def run(self, request):
                del request
                return [arm64.ScenarioResult("archive-load", "passed", "sha256:" + "1" * 64, 0)]

        with self.assertRaises(arm64.OCIArm64HarnessError):
            arm64.run_harness(self.spec, IncompleteRunner())


if __name__ == "__main__":
    unittest.main()
