from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


class AgentPolicyTests(unittest.TestCase):
    def test_durable_agent_policy_is_public_and_trace_ledgers_are_untracked(self) -> None:
        instructions = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for heading in (
            "## Provider credential boundary",
            "## Security-sensitive code",
            "## CLI output contracts",
            "## Performance changes",
        ):
            self.assertIn(heading, instructions)

        ignore_lines = {
            line.strip()
            for line in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        }
        self.assertIn(".jules/", ignore_lines)
        for trace_name in ("bolt.md", "palette.md", "sentinel.md"):
            self.assertFalse((REPO_ROOT / ".jules" / trace_name).exists())

    def test_security_policy_uses_current_channel_without_personal_contact(self) -> None:
        policy = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("latest stable release", policy)
        self.assertIn("security/advisories/new", policy)
        self.assertNotRegex(policy, r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}")
        self.assertNotIn("0.1.x", policy)

    def test_documented_actions_are_pinned_and_provider_writes_are_executor_only(self) -> None:
        doc_paths = (
            REPO_ROOT / "docs/src/content/docs/integrations/github-actions.md",
            REPO_ROOT / "docs/src/content/docs/guide/diff.md",
        )
        documents = [path.read_text(encoding="utf-8") for path in doc_paths]
        uses = [
            action
            for document in documents
            for action in re.findall(r"uses:\s+([^\s]+)", document)
        ]
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("sync --to=github", documents[0])
        for document in documents:
            self.assertIn("install.sh | sh", document)

    def test_unverified_nix_and_aqua_channels_are_not_advertised(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        channel_doc = (
            REPO_ROOT / "docs/src/content/docs/contributing/nix-and-aqua.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("mise use -g aqua:n24q02m/skret", readme)
        self.assertNotIn("nix shell github:n24q02m/skret", readme)
        self.assertNotIn("nix run github:n24q02m/skret", channel_doc)
        self.assertIn("not currently published", channel_doc)
        self.assertFalse((REPO_ROOT / "flake.nix").exists())

    def test_install_and_credential_docs_match_current_boundaries(self) -> None:
        installation = (
            REPO_ROOT / "docs/src/content/docs/guide/installation.md"
        ).read_text(encoding="utf-8")
        faq = (REPO_ROOT / "docs/src/content/docs/faq.md").read_text(encoding="utf-8")
        self.assertNotIn("docker pull ghcr.io/n24q02m/skret:latest", installation)
        self.assertNotIn("skret version skret 1.12.0", installation)
        self.assertIn("OCI Image Status", installation)
        self.assertIn("It can.", faq)
        self.assertIn("security executor", faq)


if __name__ == "__main__":
    unittest.main()
