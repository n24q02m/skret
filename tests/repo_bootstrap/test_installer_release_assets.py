"""Guards for shipping the one-shot installers as release assets.

The documented install command is ``curl -fsSL <release>/install.sh | sh``, so
the installer has to be a create-once asset of every release. These tests fail
when the wiring is dropped: the prepare lane stops staging the scripts, the
publish lane stops accepting them into its allowlist, the release smoke stops
installing the published asset, or the documentation drifts back to a URL that
is not backed by a release asset.
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"
INSTALL_SH = REPO_ROOT / "install.sh"
INSTALL_PS1 = REPO_ROOT / "install.ps1"
README = REPO_ROOT / "README.md"
DOCS = (
    REPO_ROOT / "docs" / "src" / "content" / "docs" / "guide" / "installation.md",
    REPO_ROOT / "docs" / "src" / "content" / "docs" / "index.mdx",
    REPO_ROOT / "docs" / "src" / "content" / "docs" / "integrations" / "github-actions.md",
)
RELEASE_DOWNLOAD = "https://github.com/n24q02m/skret/releases/latest/download"
ASSET_NAMES = ("install.sh", "install.sh.sha256", "install.ps1", "install.ps1.sha256")


class InstallerReleaseAssetTests(unittest.TestCase):
    def workflow(self) -> str:
        return CD_WORKFLOW.read_text(encoding="utf-8")

    def prepare_lane(self) -> str:
        return self.workflow().split("\n  publish:", 1)[0]

    def publish_lane(self) -> str:
        return self.workflow().split("\n  publish:", 1)[1]

    def installer_smoke_lane(self) -> str:
        return self.workflow().split("\n  installer-smoke:", 1)[1]

    def test_prepare_stages_both_installers_into_the_asset_directory(self) -> None:
        prepare = self.prepare_lane()
        self.assertIn("name: Stage installer scripts as release assets", prepare)
        # One loop over both scripts: a release that ships only the Unix script
        # would still pass a per-file check, so the pair is asserted together.
        self.assertIn("for script in install.sh install.ps1; do", prepare)
        self.assertIn('cp "$script" "dist/$script"', prepare)
        self.assertIn('sha256sum --text "$script" > "$script.sha256"', prepare)
        self.assertIn('test -s "dist/$script"', prepare)
        self.assertIn('test -s "dist/$script.sha256"', prepare)
        # Staging has to land before the artifact manifest so the new assets are
        # covered by auxiliary-checksums.txt and artifact-manifest.json.
        self.assertLess(
            prepare.index("name: Stage installer scripts as release assets"),
            prepare.index("name: Generate artifact manifest"),
        )

    def test_prepare_uploads_the_staged_installers_to_the_publish_lane(self) -> None:
        prepare = self.prepare_lane()
        upload = prepare.split("name: Upload installer artifacts", 1)[1].split("- name:", 1)[0]
        for asset in ASSET_NAMES:
            self.assertIn(f"dist/{asset}", upload)
        self.assertIn("if-no-files-found: error", upload)

    def test_publish_allowlist_accepts_the_installer_assets(self) -> None:
        publish = self.publish_lane()
        fixed_names = publish.split("fixed_names = {", 1)[1].split("}", 1)[0]
        for name in ASSET_NAMES:
            self.assertIn(f'"{name}"', fixed_names)

    def test_publish_refuses_a_sidecar_that_does_not_describe_its_script(self) -> None:
        publish = self.publish_lane()
        self.assertIn('for script in ("install.ps1", "install.sh"):', publish)
        self.assertIn('(dist / f"{script}.sha256").read_text', publish)
        self.assertIn("does not describe the published", publish)

    def test_release_smoke_installs_the_published_assets_not_the_checkout(self) -> None:
        smoke = self.installer_smoke_lane()
        self.assertIn("releases/download/$CANDIDATE_TAG", smoke)
        for asset in ASSET_NAMES:
            self.assertIn(f'"$base/{asset}"', smoke)
        self.assertIn('sha256sum "$RUNNER_TEMP/install.sh"', smoke)
        self.assertIn('shasum -a 256 "$RUNNER_TEMP/install.sh"', smoke)
        self.assertIn("Get-FileHash -Algorithm SHA256", smoke)
        self.assertNotIn("./install.sh", smoke)
        self.assertNotIn(".\\install.ps1", smoke)

    def test_docs_install_commands_point_at_release_assets(self) -> None:
        installation = DOCS[0].read_text(encoding="utf-8")
        self.assertIn(f"curl -fsSL {RELEASE_DOWNLOAD}/install.sh | sh", installation)
        self.assertIn(f"iwr -useb {RELEASE_DOWNLOAD}/install.ps1 | iex", installation)
        self.assertIn("install.sh.sha256", installation)
        self.assertIn("install.ps1.sha256", installation)
        # The package managers stay documented as the alternative channel.
        self.assertIn("brew install n24q02m/tap/skret", installation)
        self.assertIn("scoop install skret", installation)

        for page in (README, DOCS[0], DOCS[1]):
            text = page.read_text(encoding="utf-8")
            self.assertIn("releases/latest/download/install.sh", text, page.name)
            self.assertIn("releases/latest/download/install.ps1", text, page.name)
        self.assertIn(
            "releases/latest/download/install.sh",
            DOCS[2].read_text(encoding="utf-8"),
            DOCS[2].name,
        )

        for page in (README, *DOCS):
            text = page.read_text(encoding="utf-8")
            # A site URL is not an asset: it resolves only while some web
            # redirect exists, and a stale redirect cannot be verified from a
            # release. Every documented command must name the release asset.
            self.assertNotIn("skret.n24q02m.com/install.", text, page.name)

    def test_installers_still_verify_the_signed_archive_manifest(self) -> None:
        for script in (INSTALL_SH, INSTALL_PS1):
            source = script.read_text(encoding="utf-8")
            self.assertIn("checksums.txt", source, script.name)
            self.assertIn("checksums.txt.bundle", source, script.name)
            self.assertIn("SKRET_INSECURE_SKIP_VERIFY", source, script.name)

    @unittest.skipUnless(shutil.which("sh"), "sh is required for the POSIX syntax check")
    def test_install_sh_passes_posix_syntax_check(self) -> None:
        result = subprocess.run(
            [shutil.which("sh"), "-n", str(INSTALL_SH)],
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for the PowerShell syntax check")
    def test_install_ps1_passes_powershell_parser_check(self) -> None:
        parser = (
            "$errors = $null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{INSTALL_PS1.as_posix()}', [ref]$null, [ref]$errors); "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
        )
        result = subprocess.run(
            [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-Command", parser],
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
