from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"
G1_SHA = "291a5b6222bc9c13c184953469f8389f24b02c37"


class CandidateReleaseWorkflowTests(unittest.TestCase):
    def workflow(self) -> str:
        return CD_WORKFLOW.read_text(encoding="utf-8")

    def test_release_is_dispatch_only_and_has_prepare_publish_lanes(self) -> None:
        workflow = self.workflow()
        trigger_block = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger_block)
        self.assertNotRegex(trigger_block, r"(?m)^  push:")
        self.assertIn("group: skret-release-prepare", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("\n  prepare:", workflow)
        self.assertIn("\n  publish:", workflow)
        self.assertIn("\n  installer-smoke:", workflow)

    def test_prepare_is_credential_free_and_builds_without_publication(self) -> None:
        prepare, publish = self.workflow().split("\n  publish:", 1)
        self.assertIn("contents: read", prepare)
        self.assertNotIn("contents: write", prepare)
        self.assertNotIn("environment:", prepare)
        for flag in ("commit: true", "tag: true", "push: false", "vcs_release: false"):
            self.assertIn(flag, prepare)
        self.assertNotIn("no_operation_mode: true", prepare)
        self.assertIn(
            "args: release --clean --skip=publish -f .goreleaser.prepare.yaml",
            prepare,
        )
        for marker in (
            "secrets.",
            "gh release",
            "docker push",
            "wrangler containers push",
            "command: deploy",
        ):
            self.assertNotIn(marker, prepare)
        self.assertIn("contents: write", publish)

    def test_release_uses_exact_signed_g1_actions(self) -> None:
        workflow = self.workflow()
        version_pin = f"n24q02m/better-semantic-release@{G1_SHA}"
        publisher_pin = f"n24q02m/better-semantic-release/publish-action@{G1_SHA}"
        self.assertEqual(workflow.count(version_pin), 1)
        self.assertEqual(workflow.count(publisher_pin), 1)
        self.assertNotIn("python-semantic-release/publish-action", workflow)
        for reference in re.findall(r"uses:\s+([^\s#]+)", workflow):
            if reference.startswith("n24q02m/better-semantic-release"):
                self.assertRegex(reference.rsplit("@", 1)[-1], r"^[0-9a-f]{40}$")

    def test_prepare_bundles_the_local_release_commit_and_tag(self) -> None:
        prepare = self.workflow().split("\n  publish:", 1)[0]
        for marker in (
            "refs/heads/release-candidate",
            "dist/release.git.bundle",
            "dist/release-git.json",
            "git bundle create",
            "release_commit",
            "base_source_sha",
            "tag_object",
        ):
            self.assertIn(marker, prepare)

    def test_publish_action_is_the_only_release_asset_writer(self) -> None:
        publish = self.workflow().split("\n  publish:", 1)[1]
        self.assertIn('"schema_version": "bsr-release-manifest/v1"', publish)
        self.assertIn("body_sha256", publish)
        self.assertIn("asset_set", publish)
        self.assertIn("manifest: release-manifest.json", publish)
        self.assertIn("token: ${{ steps.app-token.outputs.token }}", publish)
        self.assertNotIn("gh release upload", publish)
        self.assertNotIn("--clobber", publish)

    def test_publish_atomically_pushes_and_binds_prepared_identity(self) -> None:
        publish = self.workflow().split("\n  publish:", 1)[1]
        for marker in (
            "needs: [prepare]",
            "EXPECTED_VERSION: ${{ needs.prepare.outputs.version }}",
            "EXPECTED_TAG: ${{ needs.prepare.outputs.tag }}",
            "EXPECTED_SHA: ${{ github.sha }}",
            "git bundle verify",
            "git push --atomic",
            "refs/heads/release-candidate:refs/heads/main",
            'git rev-parse "refs/tags/$EXPECTED_TAG^{commit}"',
            "steps.publisher.outputs.transaction_id",
            "steps.publisher.outputs.asset_set_sha256",
            "steps.publisher.outputs.result_sha256",
        ):
            self.assertIn(marker, publish)

    def test_cosign_is_pinned_and_verified_before_signing_or_install(self) -> None:
        workflow = self.workflow()
        installer = (
            "sigstore/cosign-installer@"
            "6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2"
        )
        self.assertEqual(workflow.count(installer), 2)
        self.assertEqual(workflow.count("cosign-release: v3.0.6"), 2)
        verifier = "verify_cosign_version.py v3.0.6"
        self.assertEqual(workflow.count(verifier), 2)
        self.assertLess(
            workflow.index(verifier),
            workflow.index("cosign sign-blob --yes"),
        )
        installer_smoke = workflow.split("\n  installer-smoke:", 1)[1]
        self.assertLess(
            installer_smoke.index(verifier),
            installer_smoke.index("Install exact candidate (Unix)"),
        )


if __name__ == "__main__":
    unittest.main()
