import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "update_taps.py"
SPEC = importlib.util.spec_from_file_location("update_taps", SCRIPT)
assert SPEC and SPEC.loader
update_taps = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update_taps)

OLD = "0" * 64
PLATFORMS = ("darwin_arm64", "darwin_amd64", "linux_arm64", "linux_amd64")
CASK = f"""cask "skret" do
  version "1.0.0"

  on_macos do
    on_arm do
      sha256 "{OLD}"
      url "https://github.com/n24q02m/skret/releases/download/v#{{version}}/skret_#{{version}}_darwin_arm64.tar.gz"
    end
    on_intel do
      sha256 "{OLD}"
      url "https://github.com/n24q02m/skret/releases/download/v#{{version}}/skret_#{{version}}_darwin_amd64.tar.gz"
    end
  end
  on_linux do
    on_arm do
      sha256 "{OLD}"
      url "https://github.com/n24q02m/skret/releases/download/v#{{version}}/skret_#{{version}}_linux_arm64.tar.gz"
    end
    on_intel do
      sha256 "{OLD}"
      url "https://github.com/n24q02m/skret/releases/download/v#{{version}}/skret_#{{version}}_linux_amd64.tar.gz"
    end
  end
end
"""
SCOOP = json.dumps(
    {
        "version": "1.0.0",
        "architecture": {
            "64bit": {
                "url": "https://github.com/n24q02m/skret/releases/download/v1.0.0/skret_1.0.0_windows_amd64.zip",
                "bin": ["skret.exe"],
                "hash": OLD,
            },
            "arm64": {
                "url": "https://github.com/n24q02m/skret/releases/download/v1.0.0/skret_1.0.0_windows_arm64.zip",
                "bin": ["skret.exe"],
                "hash": OLD,
            },
        },
        "license": "Apache-2.0",
    },
    indent=4,
)
NAMES = [f"skret_2.3.4_{p}.tar.gz" for p in PLATFORMS] + [
    "skret_2.3.4_windows_amd64.zip",
    "skret_2.3.4_windows_arm64.zip",
]
SUMS = {name: f"{index + 1:064x}" for index, name in enumerate(NAMES)}
CHECKSUMS = "".join(f"{digest}  {name}\n" for name, digest in SUMS.items())


class UpdateTapsTests(unittest.TestCase):
    def test_cask_and_manifest_take_version_and_each_archive_checksum(self) -> None:
        sums = update_taps.parse_checksums(CHECKSUMS)
        cask = update_taps.update_cask(CASK, "2.3.4", sums)
        scoop = json.loads(update_taps.update_scoop(SCOOP, "2.3.4", sums))

        self.assertIn('version "2.3.4"', cask)
        self.assertNotIn(OLD, cask)
        for platform in PLATFORMS:
            digest = SUMS[f"skret_2.3.4_{platform}.tar.gz"]
            expected = f'sha256 "{digest}"\n      url ".*skret_#{{version}}_{platform}'
            self.assertRegex(cask, expected)
        self.assertEqual(scoop["version"], "2.3.4")
        self.assertEqual(
            scoop["architecture"]["64bit"]["hash"], SUMS["skret_2.3.4_windows_amd64.zip"]
        )
        self.assertEqual(
            scoop["architecture"]["arm64"]["url"],
            "https://github.com/n24q02m/skret/releases/download/v2.3.4/skret_2.3.4_windows_arm64.zip",
        )
        self.assertEqual(scoop["architecture"]["arm64"]["bin"], ["skret.exe"])

    def test_missing_archive_checksum_fails_before_any_write(self) -> None:
        sums = update_taps.parse_checksums(CHECKSUMS)
        del sums["skret_2.3.4_linux_arm64.tar.gz"]
        with self.assertRaisesRegex(ValueError, "linux_arm64"):
            update_taps.update_cask(CASK, "2.3.4", sums)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sums").write_text(
                "".join(
                    f"{d}  {n}\n"
                    for n, d in SUMS.items()
                    if n != "skret_2.3.4_windows_arm64.zip"
                ),
                encoding="utf-8",
            )
            (root / "cask.rb").write_text(CASK, encoding="utf-8")
            (root / "skret.json").write_text(SCOOP, encoding="utf-8")
            code = update_taps.main(
                [
                    "--tag", "v2.3.4",
                    "--checksums", str(root / "sums"),
                    "--cask", str(root / "cask.rb"),
                    "--scoop", str(root / "skret.json"),
                ]
            )
            self.assertEqual(code, 1)
            self.assertEqual((root / "cask.rb").read_text(encoding="utf-8"), CASK)
            self.assertEqual((root / "skret.json").read_text(encoding="utf-8"), SCOOP)

    def test_only_stable_release_tags_are_accepted(self) -> None:
        self.assertEqual(update_taps.parse_tag("v2.3.4"), "2.3.4")
        for tag in ("v2.3.4-beta.1", "2.3.4", "v2.3", "latest"):
            with self.assertRaises(ValueError, msg=tag):
                update_taps.parse_tag(tag)

    def test_rewriting_the_same_release_is_a_no_op(self) -> None:
        sums = update_taps.parse_checksums(CHECKSUMS)
        cask = update_taps.update_cask(CASK, "2.3.4", sums)
        scoop = update_taps.update_scoop(SCOOP, "2.3.4", sums)
        self.assertEqual(update_taps.update_cask(cask, "2.3.4", sums), cask)
        self.assertEqual(update_taps.update_scoop(scoop, "2.3.4", sums), scoop)


if __name__ == "__main__":
    unittest.main()
