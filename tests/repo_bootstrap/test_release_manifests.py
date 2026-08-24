from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "release_manifests.py"


def load_module():
    spec = importlib.util.spec_from_file_location("release_manifests", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release manifest module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manifests = load_module()


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.root.mkdir()
        (self.root / "b.txt").write_bytes(b"second")
        (self.root / "a.txt").write_bytes(b"first")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_inventory_is_sorted_and_rerun_is_deterministic(self) -> None:
        first = manifests.build_manifest(
            "source",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
        )
        second = manifests.build_manifest(
            "source",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
        )
        self.assertEqual(first, second)
        self.assertEqual([row["path"] for row in first["files"]], ["a.txt", "b.txt"])
        self.assertEqual(first["files"][0]["length"], 5)
        self.assertEqual(first["files"][0]["sha256"], hashlib.sha256(b"first").hexdigest())
        self.assertTrue(first["merkle_root"].startswith("sha256:"))

    def test_file_addition_removal_and_tamper_change_manifest(self) -> None:
        base = manifests.build_manifest(
            "artifact",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            source_manifest_digest="sha256:" + "b" * 64,
        )
        (self.root / "c.txt").write_bytes(b"third")
        added = manifests.build_manifest(
            "artifact",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            source_manifest_digest="sha256:" + "b" * 64,
        )
        self.assertNotEqual(base["merkle_root"], added["merkle_root"])
        (self.root / "a.txt").unlink()
        removed = manifests.build_manifest(
            "artifact",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            source_manifest_digest="sha256:" + "b" * 64,
        )
        self.assertNotEqual(added["merkle_root"], removed["merkle_root"])
        (self.root / "b.txt").write_bytes(b"tampered")
        tampered = manifests.build_manifest(
            "artifact",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            source_manifest_digest="sha256:" + "b" * 64,
        )
        self.assertNotEqual(removed["merkle_root"], tampered["merkle_root"])

    def test_symlink_and_traversal_are_rejected(self) -> None:
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_bytes(b"outside")
        try:
            (self.root / "link.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(manifests.ManifestError):
            manifests.inventory(self.root)
        with self.assertRaises(manifests.ManifestError):
            manifests.inventory(self.root, excludes=["../outside.txt"])

    def test_excluded_manifest_paths_do_not_recurse(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "manifest.json").write_bytes(b"self")
        (nested / "signature.sig").write_bytes(b"sig")
        manifest = manifests.build_manifest(
            "deployment",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            source_manifest_digest="sha256:" + "b" * 64,
            excludes=["nested/manifest.json", "nested/signature.sig"],
        )
        self.assertNotIn("nested/manifest.json", [row["path"] for row in manifest["files"]])
        self.assertNotIn("nested/signature.sig", [row["path"] for row in manifest["files"]])

    def test_merkle_order_is_bound(self) -> None:
        rows = [
            {"path": "a", "length": 1, "sha256": "0" * 64},
            {"path": "b", "length": 1, "sha256": "1" * 64},
        ]
        self.assertNotEqual(
            manifests.merkle_root(rows),
            manifests.merkle_root(list(reversed(rows))),
        )

    def test_atomic_conflict_preserves_existing_bytes(self) -> None:
        output = self.root / "manifest.json"
        digest = self.root / "manifest.sha256"
        value = manifests.build_manifest(
            "source",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            excludes=["manifest.json", "manifest.sha256"],
        )
        manifests.write_manifest(value, output, digest)
        original = output.read_bytes()
        with self.assertRaises(manifests.ManifestConflict):
            manifests.write_manifest({**value, "tag": "v1.2.4"}, output, digest)
        self.assertEqual(output.read_bytes(), original)

    def test_foreign_output_lock_is_never_removed(self) -> None:
        manifest = manifests.build_manifest(
            "source",
            self.root,
            source_sha="a" * 40,
            version="1.2.3",
            tag="v1.2.3",
            channel="beta",
            excludes=["locked.json.lock"],
        )
        output = self.root / "locked.json"
        lock = Path(str(output) + ".lock")
        lock.write_bytes(b"foreign-owner")
        with self.assertRaises(manifests.ManifestConflict):
            manifests.write_manifest(manifest, output)
        self.assertEqual(lock.read_bytes(), b"foreign-owner")
        self.assertFalse(output.exists())

    def test_manifest_kind_bindings_and_persistence_fail_closed(self) -> None:
        with self.assertRaises(manifests.ManifestError):
            manifests.build_manifest(
                "source",
                self.root,
                source_sha="a" * 40,
                version="1.2.3",
                tag="v1.2.3",
                channel="beta",
                source_manifest_digest="sha256:" + "b" * 64,
            )
        with self.assertRaises(manifests.ManifestError):
            manifests.write_manifest(
                {"schema": "skret-release-manifest/v1", "kind": "source"},
                self.root / "invalid.json",
            )
        self.assertFalse((self.root / "invalid.json").exists())

    def test_cli_policy_is_prepare_only(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "cd.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release_manifests.py", workflow)
        self.assertIn("source-manifest.json", workflow)
        self.assertIn("artifact-manifest.json", workflow)
        self.assertIn("skret-deployment-manifest.json", workflow)
        self.assertNotIn("publish-action", workflow)
        self.assertNotIn("docker push", workflow)

    def test_cli_generates_canonical_json_and_digest(self) -> None:
        output = self.root / "source-manifest.json"
        digest = self.root / "source-manifest.sha256"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "source",
                "--root",
                str(self.root),
                "--output",
                str(output),
                "--digest-output",
                str(digest),
                "--source-sha",
                "a" * 40,
                "--version",
                "1.2.3",
                "--tag",
                "v1.2.3",
                "--channel",
                "beta",
                "--exclude",
                "source-manifest.json",
                "--exclude",
                "source-manifest.sha256",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        encoded = output.read_bytes()
        self.assertEqual(json.dumps(json.loads(encoded), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(), encoded)
        self.assertEqual(digest.read_text(encoding="ascii").strip(), hashlib.sha256(encoded).hexdigest())


if __name__ == "__main__":
    unittest.main()
