import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLISH_CONFIG = REPO_ROOT / ".goreleaser.yaml"
PREPARE_CONFIG = REPO_ROOT / ".goreleaser.prepare.yaml"
SEMANTIC_RELEASE_CONFIG = REPO_ROOT / "semantic-release.toml"

PARITY_SECTIONS = ("builds", "archives", "checksum", "sboms")
TOP_LEVEL_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def top_level_keys(source: str) -> list[str]:
    keys: list[str] = []
    for line in source.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        key, separator, _ = line.partition(":")
        if separator and TOP_LEVEL_KEY.fullmatch(key):
            keys.append(key)
    return keys


def section_text(source: str, name: str) -> str:
    lines = source.splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if not line[:1].isspace() and line.startswith(f"{name}:")
    )
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            end = index
            break
    return "\n".join(
        line.rstrip()
        for line in lines[start:end]
        if line.strip() and not line.lstrip().startswith("#")
    )


class ReleasePolicyTests(unittest.TestCase):
    def test_prepare_preserves_build_input_parity(self) -> None:
        publish = PUBLISH_CONFIG.read_text(encoding="utf-8")
        prepare = PREPARE_CONFIG.read_text(encoding="utf-8")

        for section in PARITY_SECTIONS:
            self.assertEqual(
                section_text(publish, section),
                section_text(prepare, section),
                f"prepare config drifted from publish config in {section}",
            )

    def test_prepare_has_no_publish_sign_announce_or_replacement_path(self) -> None:
        source = PREPARE_CONFIG.read_text(encoding="utf-8")
        keys = set(top_level_keys(source))

        for forbidden in (
            "release",
            "signs",
            "homebrew_casks",
            "scoops",
            "announce",
            "announcements",
            "brews",
            "dockers",
            "dockers_v2",
            "docker_manifests",
        ):
            self.assertNotIn(forbidden, keys)
        for forbidden_marker in (
            "replace_existing_artifacts:",
            "repository:",
            "owner:",
            "branch:",
            "token:",
            "commit_msg_template:",
            "github_urls:",
            "GITHUB_TOKEN",
            "TAP_GITHUB_TOKEN",
            "ghcr.io/",
        ):
            self.assertNotIn(forbidden_marker, source)

    def test_build_metadata_uses_commit_timestamp(self) -> None:
        expected = (
            "-X github.com/n24q02m/skret/internal/version.Date={{.CommitTimestamp}}"
        )
        for config in (PUBLISH_CONFIG, PREPARE_CONFIG):
            source = config.read_text(encoding="utf-8")
            self.assertIn(expected, source)
            self.assertNotIn("-X github.com/n24q02m/skret/internal/version.Date={{.Date}}", source)

    def test_publish_config_refuses_destructive_replacement(self) -> None:
        source = PUBLISH_CONFIG.read_text(encoding="utf-8")
        self.assertNotIn("replace_existing_artifacts:", source)
        self.assertIn("homebrew_casks:", source)
        self.assertIn("scoops:", source)
        self.assertIn("signs:", source)

    def test_semantic_release_uses_canonical_commit_message(self) -> None:
        source = SEMANTIC_RELEASE_CONFIG.read_text(encoding="utf-8")
        self.assertIn('commit_message = "fix(release): v{version} [skip ci]"', source)
        self.assertNotIn('commit_message = "feat(release):', source)


if __name__ == "__main__":
    unittest.main()
