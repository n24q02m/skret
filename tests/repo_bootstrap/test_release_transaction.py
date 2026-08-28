from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "release_transaction.py"
TX = "tx-20260824"
SOURCE = "a" * 40
ARTIFACT = "sha256:" + "b" * 64
INTENT = "sha256:" + "c" * 64
OBSERVATION = "sha256:" + "d" * 64
TIMESTAMP = "2026-08-24T00:00:00Z"


def run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def init_args(journal: Path, *, tx: str = TX, artifact: str = ARTIFACT) -> tuple[str, ...]:
    return (
        "init",
        "--journal",
        str(journal),
        "--transaction-id",
        tx,
        "--channel",
        "beta",
        "--source-sha",
        SOURCE,
        "--artifact-digest",
        artifact,
        "--intent-digest",
        INTENT,
        "--timestamp",
        TIMESTAMP,
    )


def transition_args(
    journal: Path,
    event_id: str,
    from_state: str,
    state: str,
    *,
    tx: str = TX,
    timestamp: str = TIMESTAMP,
    external_id: str | None = None,
    observation_digest: str | None = None,
) -> tuple[str, ...]:
    args: list[str] = [
        "transition",
        "--journal",
        str(journal),
        "--transaction-id",
        tx,
        "--event-id",
        event_id,
        "--from",
        from_state,
        "--to",
        state,
        "--timestamp",
        timestamp,
    ]
    if external_id is not None:
        args.extend(("--external-id", external_id))
    if observation_digest is not None:
        args.extend(("--observation-digest", observation_digest))
    return tuple(args)


def assert_success(test: unittest.TestCase, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    test.assertEqual(result.returncode, 0, result.stderr)
    test.assertEqual(result.stderr, "")
    value = json.loads(result.stdout)
    test.assertIsInstance(value, dict)
    return value


def assert_failure(test: unittest.TestCase, result: subprocess.CompletedProcess[str]) -> None:
    test.assertNotEqual(result.returncode, 0)
    test.assertEqual(result.stdout, "")
    test.assertTrue(result.stderr.startswith("error: "))


def journal_lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines()


class ReleaseTransactionTests(unittest.TestCase):
    def test_valid_lifecycle_and_value_free_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "release.jsonl"
            assert_success(self, run_cli(*init_args(journal)))
            assert_success(
                self,
                run_cli(*transition_args(journal, "approve", "prepared", "approved")),
            )
            assert_success(
                self,
                run_cli(*transition_args(journal, "dispatching", "approved", "dispatching")),
            )
            assert_success(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "dispatch",
                        "dispatching",
                        "dispatched",
                        external_id="run-123",
                    )
                ),
            )
            assert_success(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "complete",
                        "dispatched",
                        "completed",
                    )
                ),
            )
            result = assert_success(self, run_cli("status", "--journal", str(journal)))
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["sequence"], 4)
            self.assertEqual(result["transaction_id"], TX)
            self.assertEqual(result["external_id"], "run-123")
            self.assertNotIn("source_sha", result)
            self.assertNotIn("artifact_digest", result)
            self.assertNotIn("intent_digest", result)
            rendered = json.dumps(result, sort_keys=True, separators=(",", ":"))
            self.assertNotIn(SOURCE, rendered)
            self.assertNotIn(ARTIFACT, rendered)
            self.assertNotIn(INTENT, rendered)
            verified = assert_success(self, run_cli("verify", "--journal", str(journal)))
            self.assertTrue(verified["verified"])
            self.assertEqual(verified["record_hash"], result["record_hash"])

    def test_invalid_transition_and_reconciliation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "release.jsonl"
            assert_success(self, run_cli(*init_args(journal)))
            assert_failure(
                self,
                run_cli(*transition_args(journal, "bad", "approved", "dispatching")),
            )
            assert_success(
                self,
                run_cli(*transition_args(journal, "approve", "prepared", "approved")),
            )
            assert_success(
                self,
                run_cli(*transition_args(journal, "start", "approved", "dispatching")),
            )
            assert_failure(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "ambiguous",
                        "dispatching",
                        "needs_reconciliation",
                    )
                ),
            )
            assert_success(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "ambiguous",
                        "dispatching",
                        "needs_reconciliation",
                        observation_digest=OBSERVATION,
                    )
                ),
            )
            assert_failure(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "resume-without-proof",
                        "needs_reconciliation",
                        "dispatched",
                    )
                ),
            )
            assert_failure(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "resume-without-dispatch-id",
                        "needs_reconciliation",
                        "dispatched",
                        observation_digest=OBSERVATION,
                    )
                ),
            )
            resumed = assert_success(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "resume",
                        "needs_reconciliation",
                        "dispatched",
                        external_id="run-456",
                        observation_digest=OBSERVATION,
                    )
                ),
            )
            self.assertEqual(resumed["state"], "dispatched")
            self.assertEqual(resumed["observation_digest"], OBSERVATION)

    def test_duplicate_exact_event_is_idempotent_and_conflicts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "release.jsonl"
            assert_success(self, run_cli(*init_args(journal)))
            original_init_lines = len(journal_lines(journal))
            assert_success(self, run_cli(*init_args(journal)))
            self.assertEqual(len(journal_lines(journal)), original_init_lines)
            assert_failure(self, run_cli(*init_args(journal, artifact="sha256:" + "e" * 64)))

            approve = transition_args(journal, "approve", "prepared", "approved")
            assert_success(self, run_cli(*approve))
            before_duplicate = journal_lines(journal)
            assert_success(self, run_cli(*approve))
            self.assertEqual(journal_lines(journal), before_duplicate)
            assert_failure(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "approve",
                        "prepared",
                        "approved",
                        timestamp="2026-08-24T00:00:01Z",
                    )
                ),
            )
            assert_failure(
                self,
                run_cli(
                    *transition_args(
                        journal,
                        "foreign",
                        "approved",
                        "dispatching",
                        tx="tx-other",
                    )
                ),
            )

    def test_strict_lengths_characters_digests_and_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "release.jsonl"
            invalid_cases: Iterable[tuple[str, ...]] = (
                init_args(journal, tx="contains whitespace"),
                init_args(journal, artifact="sha256:" + "A" * 64),
                (
                    "init",
                    "--journal",
                    str(journal),
                    "--transaction-id",
                    TX,
                    "--channel",
                    "beta",
                    "--source-sha",
                    "a" * 39,
                    "--artifact-digest",
                    ARTIFACT,
                    "--intent-digest",
                    INTENT,
                    "--timestamp",
                    "2026-02-30T00:00:00Z",
                ),
                (
                    "init",
                    "--journal",
                    str(journal),
                    "--transaction-id",
                    TX,
                    "--channel",
                    "beta",
                    "--source-sha",
                    SOURCE,
                    "--artifact-digest",
                    ARTIFACT,
                    "--intent-digest",
                    INTENT,
                    "--timestamp",
                    "2026-08-24T00:00:00",
                ),
            )
            for args in invalid_cases:
                assert_failure(self, run_cli(*args))
            self.assertFalse(journal.exists())

    def test_corrupt_partial_and_reordered_tails_fail_closed(self) -> None:
        def make_lifecycle(path: Path) -> None:
            assert_success(self, run_cli(*init_args(path)))
            assert_success(self, run_cli(*transition_args(path, "approve", "prepared", "approved")))
            assert_success(self, run_cli(*transition_args(path, "start", "approved", "dispatching")))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corrupt = root / "corrupt.jsonl"
            make_lifecycle(corrupt)
            raw = corrupt.read_bytes()
            corrupt.write_bytes(raw[:-3] + (b"0" if raw[-3:-2] != b"0" else b"1") + raw[-2:])
            assert_failure(self, run_cli("verify", "--journal", str(corrupt)))
            assert_failure(self, run_cli(*transition_args(corrupt, "next", "dispatching", "dispatched")))

            partial = root / "partial.jsonl"
            make_lifecycle(partial)
            with partial.open("ab") as stream:
                stream.write(b'{"partial":true}')
            assert_failure(self, run_cli("status", "--journal", str(partial)))

            reordered = root / "reordered.jsonl"
            make_lifecycle(reordered)
            lines = reordered.read_bytes().splitlines(keepends=True)
            reordered.write_bytes(lines[0] + lines[2] + lines[1])
            assert_failure(self, run_cli("verify", "--journal", str(reordered)))

            noncanonical = root / "noncanonical.jsonl"
            make_lifecycle(noncanonical)
            first = json.loads(noncanonical.read_bytes().splitlines()[0])
            noncanonical.write_bytes(
                json.dumps(first, indent=2).encode("utf-8") + b"\n" + b"".join(
                    noncanonical.read_bytes().splitlines(keepends=True)[1:]
                )
            )
            assert_failure(self, run_cli("verify", "--journal", str(noncanonical)))

    def test_concurrent_exact_writers_append_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "release.jsonl"
            assert_success(self, run_cli(*init_args(journal)))
            args = transition_args(
                journal,
                "dispatch",
                "prepared",
                "approved",
            )
            # The first process appends; all later processes observe the exact
            # event and return idempotently while holding the same lock.
            def invoke(_: int) -> subprocess.CompletedProcess[str]:
                return run_cli(*args)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(invoke, range(8)))
            for result in results:
                assert_success(self, result)
            self.assertEqual(len(journal_lines(journal)), 2)

    def test_fault_points_are_fail_closed_and_resume_without_duplicate_dispatch(self) -> None:
        for point in ("before_append", "after_flush", "before_fsync"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                journal = Path(temporary) / "release.jsonl"
                assert_success(self, run_cli(*init_args(journal)))
                dispatch = transition_args(journal, "dispatch", "prepared", "approved")
                env = os.environ.copy()
                env["RELEASE_TRANSACTION_FAULT"] = point
                failed = run_cli(*dispatch, env=env)
                assert_failure(self, failed)
                if point == "before_append":
                    self.assertEqual(len(journal_lines(journal)), 1)
                else:
                    self.assertEqual(len(journal_lines(journal)), 2)
                env.pop("RELEASE_TRANSACTION_FAULT")
                assert_success(self, run_cli(*dispatch, env=env))
                self.assertEqual(len(journal_lines(journal)), 2)


if __name__ == "__main__":
    unittest.main()
