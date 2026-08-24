from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
