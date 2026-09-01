import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import candidate_git_control as control  # noqa: E402
from candidate_trust import (  # noqa: E402
    canonical_json_bytes,
    generate_keypair,
    sign_bytes,
    verify_bytes,
)

EXECUTOR = SCRIPTS / "candidate_git_control.py"


class CandidateGitControlTests(unittest.TestCase):
    def test_executor_applies_atomic_cas_and_proves_denials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            synthetic = root / "synthetic.git"
            production = root / "production.git"
            observer = root / "observer"
            self.git(root, "init", "--bare", str(synthetic))
            self.git(root, "init", "--bare", str(production))
            self.git(root, "init", str(work))
            self.git(root, "init", str(observer))
            self.git(work, "config", "user.name", "Candidate Fixture")
            self.git(work, "config", "user.email", "candidate@example.invalid")

            commits = [self.commit(work, index) for index in range(1, 5)]
            transaction = "bd-control-20260901"
            namespace = f"refs/heads/bdrive-candidate/{transaction}/"
            operations = [
                {
                    "ref": namespace + "lease",
                    "expected_oid": commits[0],
                    "desired_oid": commits[1],
                },
                {
                    "ref": namespace + "retention",
                    "expected_oid": commits[2],
                    "desired_oid": commits[3],
                },
            ]
            self.git(
                work,
                "push",
                synthetic.as_uri(),
                f"{commits[0]}:{operations[0]['ref']}",
                f"{commits[2]}:{operations[1]['ref']}",
                f"{commits[0]}:refs/heads/main",
            )
            self.git(
                work,
                "push",
                production.as_uri(),
                f"{commits[0]}:{operations[0]['ref']}",
                f"{commits[2]}:{operations[1]['ref']}",
                f"{commits[0]}:refs/heads/main",
                f"{commits[0]}:refs/heads/production-only",
            )

            issuer_private, issuer_public = generate_keypair(bytes(range(32)))
            executor_private, executor_public = generate_keypair(bytes(range(32, 64)))
            now = datetime.now(UTC).replace(microsecond=0)
            remote_url = synthetic.as_uri()
            capability = {
                "schema_version": 1,
                "purpose": "BD-CANDIDATE-CONTROL-V1",
                "transaction_id": transaction,
                "issuer": "skret-candidate-issuer",
                "executor_id": "skret-candidate-executor-1",
                "executor_public_key": executor_public.hex(),
                "client_id": "better-drive-candidate-client-1",
                "remote": "n24q02m/synthetic-control",
                "remote_url_digest": hashlib.sha256(remote_url.encode()).hexdigest(),
                "ref_namespace": namespace,
                "claim_ref": namespace + "claim",
                "completion_ref": namespace + "completion",
                "operations": operations,
                "operation_budget": len(operations),
                "ref_escape_probe": "refs/heads/main",
                "production_remote": "n24q02m/production-control",
                "production_ref": "refs/heads/main",
                "teardown_intent_digest": "a" * 64,
                "issued_at": self.timestamp(now - timedelta(minutes=1)),
                "expires_at": self.timestamp(now + timedelta(minutes=10)),
                "nonce": "bd-control-nonce-1",
            }
            capability["signature"] = sign_bytes(
                canonical_json_bytes(capability), issuer_private
            ).hex()

            capability_path = root / "capability.json"
            issuer_key_path = root / "issuer.pub"
            executor_key_path = root / "executor.key"
            capability_path.write_bytes(canonical_json_bytes(capability) + b"\n")
            issuer_key_path.write_bytes(issuer_public)
            executor_key_path.write_bytes(executor_private)

            production_url = "https://github.com/n24q02m/production-control.git"
            mismatched_capability = dict(capability)
            mismatched_capability["remote_url_digest"] = hashlib.sha256(
                production_url.encode()
            ).hexdigest()
            mismatched_capability.pop("signature")
            mismatched_capability["signature"] = sign_bytes(
                canonical_json_bytes(mismatched_capability),
                issuer_private,
            ).hex()
            mismatched_capability_path = root / "mismatched-capability.json"
            mismatched_capability_path.write_bytes(
                canonical_json_bytes(mismatched_capability) + b"\n"
            )
            blocked_route = subprocess.run(
                [
                    sys.executable,
                    str(EXECUTOR),
                    "--capability",
                    str(mismatched_capability_path),
                    "--issuer-public-key",
                    str(issuer_key_path),
                    "--executor-private-key",
                    str(executor_key_path),
                    "--repository",
                    str(work),
                    "--remote-url",
                    production_url,
                    "--git-token-file",
                    str(root / "unused-token"),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(blocked_route.returncode, 0)
            self.assertEqual(blocked_route.stdout, "")
            self.assertIn(
                "GitHub remote identity",
                blocked_route.stderr,
            )

            command = [
                sys.executable,
                str(EXECUTOR),
                "--capability",
                str(capability_path),
                "--issuer-public-key",
                str(issuer_key_path),
                "--executor-private-key",
                str(executor_key_path),
                "--repository",
                str(work),
                "--remote-url",
                remote_url,
                "--allow-file-fixture",
            ]
            uppercase_signature_capability = json.loads(json.dumps(capability))
            uppercase_signature_capability["signature"] = (
                uppercase_signature_capability["signature"].upper()
            )
            fractional_timestamp_capability = json.loads(json.dumps(capability))
            fractional_timestamp_capability["issued_at"] = (
                fractional_timestamp_capability["issued_at"].removesuffix("Z")
                + ".000000Z"
            )
            fractional_timestamp_capability.pop("signature")
            fractional_timestamp_capability["signature"] = sign_bytes(
                canonical_json_bytes(fractional_timestamp_capability),
                issuer_private,
            ).hex()
            for name, invalid_capability, error_fragment in (
                (
                    "uppercase-signature",
                    uppercase_signature_capability,
                    "signature is invalid",
                ),
                (
                    "fractional-timestamp",
                    fractional_timestamp_capability,
                    "timestamp is invalid",
                ),
            ):
                invalid_capability_path = root / f"{name}-capability.json"
                invalid_capability_path.write_bytes(
                    canonical_json_bytes(invalid_capability) + b"\n"
                )
                invalid_capability_command = list(command)
                invalid_capability_command[3] = str(invalid_capability_path)
                blocked_capability = subprocess.run(
                    invalid_capability_command,
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(blocked_capability.returncode, 0)
                self.assertEqual(blocked_capability.stdout, "")
                self.assertIn(error_fragment, blocked_capability.stderr)
            tag_capability = json.loads(json.dumps(capability))
            tag_namespace = namespace.replace("refs/heads/", "refs/tags/", 1)
            tag_capability["ref_namespace"] = tag_namespace
            tag_capability["claim_ref"] = tag_namespace + "claim"
            tag_capability["completion_ref"] = tag_namespace + "completion"
            for operation in tag_capability["operations"]:
                operation["ref"] = operation["ref"].replace(
                    namespace,
                    tag_namespace,
                    1,
                )
            tag_capability.pop("signature")
            tag_capability["signature"] = sign_bytes(
                canonical_json_bytes(tag_capability),
                issuer_private,
            ).hex()
            tag_capability_path = root / "tag-capability.json"
            tag_capability_path.write_bytes(
                canonical_json_bytes(tag_capability) + b"\n"
            )
            tag_command = list(command)
            tag_command[3] = str(tag_capability_path)
            blocked_tag_route = subprocess.run(
                tag_command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(blocked_tag_route.returncode, 0)
            self.assertEqual(blocked_tag_route.stdout, "")
            self.assertIn("ref namespace", blocked_tag_route.stderr)
            case_alias_capability = json.loads(json.dumps(capability))
            case_alias_capability["remote"] = "N24Q02M/production-control"
            case_alias_capability.pop("signature")
            case_alias_capability["signature"] = sign_bytes(
                canonical_json_bytes(case_alias_capability),
                issuer_private,
            ).hex()
            case_alias_path = root / "case-alias-capability.json"
            case_alias_path.write_bytes(
                canonical_json_bytes(case_alias_capability) + b"\n"
            )
            case_alias_command = list(command)
            case_alias_command[3] = str(case_alias_path)
            blocked_case_alias = subprocess.run(
                case_alias_command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(blocked_case_alias.returncode, 0)
            self.assertEqual(blocked_case_alias.stdout, "")
            self.assertIn("remote is invalid", blocked_case_alias.stderr)
            token_path = root / "unused-token"
            token_path.write_text("not-used", encoding="utf-8")
            for name, invalid_url in {
                "uppercase-host": "https://GITHUB.COM/n24q02m/synthetic-control.git",
                "suffixless": "https://github.com/n24q02m/synthetic-control",
            }.items():
                invalid_url_capability = json.loads(json.dumps(capability))
                invalid_url_capability["remote_url_digest"] = hashlib.sha256(
                    invalid_url.encode()
                ).hexdigest()
                invalid_url_capability.pop("signature")
                invalid_url_capability["signature"] = sign_bytes(
                    canonical_json_bytes(invalid_url_capability),
                    issuer_private,
                ).hex()
                invalid_url_path = root / f"{name}-capability.json"
                invalid_url_path.write_bytes(
                    canonical_json_bytes(invalid_url_capability) + b"\n"
                )
                invalid_url_command = list(command)
                invalid_url_command[3] = str(invalid_url_path)
                invalid_url_command[
                    invalid_url_command.index("--remote-url") + 1
                ] = invalid_url
                invalid_url_command.remove("--allow-file-fixture")
                invalid_url_command.extend(
                    ["--git-token-file", str(token_path)]
                )
                blocked_url = subprocess.run(
                    invalid_url_command,
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(blocked_url.returncode, 0)
                self.assertEqual(blocked_url.stdout, "")
                self.assertIn("GitHub remote identity", blocked_url.stderr)

            sha256_capability = json.loads(json.dumps(capability))
            for index, operation in enumerate(sha256_capability["operations"]):
                operation["expected_oid"] = str(index + 1) * 64
                operation["desired_oid"] = str(index + 3) * 64
            sha256_capability.pop("signature")
            sha256_capability["signature"] = sign_bytes(
                canonical_json_bytes(sha256_capability),
                issuer_private,
            ).hex()
            sha256_path = root / "sha256-capability.json"
            sha256_path.write_bytes(
                canonical_json_bytes(sha256_capability) + b"\n"
            )
            sha256_command = list(command)
            sha256_command[3] = str(sha256_path)
            blocked_sha256 = subprocess.run(
                sha256_command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(blocked_sha256.returncode, 0)
            self.assertEqual(blocked_sha256.stdout, "")
            self.assertIn("OID is invalid", blocked_sha256.stderr)

            unicode_ref_capability = json.loads(json.dumps(capability))
            unicode_namespace = namespace + "é/"
            unicode_ref_capability["ref_namespace"] = unicode_namespace
            unicode_ref_capability["claim_ref"] = unicode_namespace + "claim"
            unicode_ref_capability["completion_ref"] = unicode_namespace + "completion"
            for operation in unicode_ref_capability["operations"]:
                operation["ref"] = operation["ref"].replace(
                    namespace,
                    unicode_namespace,
                    1,
                )
            unicode_ref_capability.pop("signature")
            unicode_ref_capability["signature"] = sign_bytes(
                canonical_json_bytes(unicode_ref_capability),
                issuer_private,
            ).hex()
            unicode_ref_path = root / "unicode-ref-capability.json"
            unicode_ref_path.write_bytes(
                canonical_json_bytes(unicode_ref_capability) + b"\n"
            )
            unicode_ref_command = list(command)
            unicode_ref_command[3] = str(unicode_ref_path)
            blocked_unicode = subprocess.run(
                unicode_ref_command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(blocked_unicode.returncode, 0)
            self.assertEqual(blocked_unicode.stdout, "")
            self.assertIn("ref namespace is invalid", blocked_unicode.stderr)
            self.git(
                work,
                "config",
                f"url.{production.as_uri()}.insteadOf",
                remote_url,
            )
            self.assertEqual(
                self.remote_oid(
                    work,
                    remote_url,
                    "refs/heads/production-only",
                ),
                commits[0],
            )
            processes = [
                subprocess.Popen(
                    command,
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(2)
            ]
            completed = [
                (process, *process.communicate(timeout=60)) for process in processes
            ]
            successes = [
                (process, stdout, stderr)
                for process, stdout, stderr in completed
                if process.returncode == 0
            ]
            self.assertEqual(
                len(successes),
                1,
                [(process.returncode, stderr) for process, _, stderr in completed],
            )
            self.assertTrue(
                all(
                    process.returncode != 0 and stdout == ""
                    for process, stdout, _ in completed
                    if process is not successes[0][0]
                )
            )
            _, successful_stdout, successful_stderr = successes[0]
            self.assertEqual(successful_stderr, "")
            readback = json.loads(successful_stdout)
            signature = bytes.fromhex(readback.pop("signature"))
            self.assertTrue(
                verify_bytes(canonical_json_bytes(readback), signature, executor_public)
            )
            self.assertEqual(readback["capability_digest"], self.digest(capability))
            atomic_push = readback["atomic_push"]
            self.assertTrue(atomic_push["attempted"])
            self.assertEqual(atomic_push["exit_code"], 0)
            self.assertFalse(atomic_push["reconciled"])
            claim = readback["claim"]
            completion = readback["completion"]
            self.assertEqual(
                readback["claim_payload"]["invocation_id"],
                claim["invocation_id"],
            )
            self.assertEqual(
                readback["claim_payload"]["capability_digest"],
                readback["capability_digest"],
            )
            atomic_updates = atomic_push["updates"]
            self.assertEqual(
                [update["kind"] for update in atomic_updates],
                ["claim", "operation", "operation", "completion"],
            )
            self.assertEqual(
                [update["ref"] for update in atomic_updates],
                [
                    capability["claim_ref"],
                    operations[0]["ref"],
                    operations[1]["ref"],
                    capability["completion_ref"],
                ],
            )
            self.assertEqual(atomic_updates[0]["before_oid"], None)
            self.assertEqual(atomic_updates[0]["after_oid"], claim["oid"])
            self.assertEqual(atomic_updates[-1]["before_oid"], None)
            self.assertEqual(atomic_updates[-1]["after_oid"], claim["oid"])
            self.assertEqual(claim["ref"], capability["claim_ref"])
            self.assertEqual(completion["ref"], capability["completion_ref"])
            self.assertRegex(claim["oid"], r"^[0-9a-f]{40}$")
            self.assertEqual(completion["oid"], claim["oid"])
            self.assertTrue(claim["created"])
            self.assertTrue(completion["created"])
            self.assertEqual(readback["transport"], "file-fixture")
            self.assertEqual(
                readback["replay_probe"]["outcome"],
                "ALREADY_COMPLETED",
            )
            self.assertEqual(
                readback["replay_probe"]["attempted_claim_payload"][
                    "invocation_id"
                ],
                readback["replay_probe"]["attempted_invocation_id"],
            )
            self.assertEqual(
                [update["kind"] for update in readback["replay_probe"]["updates"]],
                ["claim", "operation", "operation", "completion"],
            )
            self.assertTrue(readback["replay_probe"]["provider_invoked"])
            self.assertNotEqual(readback["replay_probe"]["exit_code"], 0)
            self.assertNotEqual(
                readback["replay_probe"]["attempted_claim_oid"],
                readback["replay_probe"]["winning_claim_oid"],
            )
            self.assertEqual(
                readback["replay_probe"]["claim_oid_before"],
                readback["replay_probe"]["claim_oid_after"],
            )
            self.assertEqual(
                readback["replay_probe"]["completion_oid_before"],
                readback["replay_probe"]["completion_oid_after"],
            )
            self.assertEqual(
                readback["replay_probe"]["operations_before"],
                readback["replay_probe"]["operations_after"],
            )
            self.assertTrue(readback["replay_probe"]["attempted"])
            denial_expectations = {
                "ref_escape_probe": (
                    capability["remote"],
                    capability["ref_escape_probe"],
                    "REF_OUTSIDE_NAMESPACE",
                ),
                "production_remote_probe": (
                    capability["production_remote"],
                    capability["production_ref"],
                    "REMOTE_OUTSIDE_ALLOWLIST",
                ),
                "production_ref_probe": (
                    capability["remote"],
                    capability["production_ref"],
                    "REF_OUTSIDE_NAMESPACE",
                ),
            }
            for name, (remote, ref, outcome) in denial_expectations.items():
                denial = readback[name]
                self.assertEqual(denial["remote"], remote)
                self.assertEqual(denial["ref"], ref)
                self.assertEqual(denial["outcome"], outcome)
                self.assertFalse(denial["provider_invoked"])
                self.assertEqual(
                    denial["provider_calls_before"],
                    denial["provider_calls_after"],
                )

            for operation in operations:
                self.assertEqual(
                    self.remote_oid(observer, remote_url, operation["ref"]),
                    operation["desired_oid"],
                )
            for operation in operations:
                self.assertEqual(
                    self.remote_oid(
                        observer,
                        production.as_uri(),
                        operation["ref"],
                    ),
                    operation["expected_oid"],
                )
            self.assertEqual(
                self.remote_oid(observer, remote_url, capability["claim_ref"]),
                claim["oid"],
            )
            self.assertEqual(
                self.remote_oid(observer, remote_url, capability["completion_ref"]),
                completion["oid"],
            )
            self.git(observer, "fetch", "--no-tags", remote_url, capability["claim_ref"])
            self.assertEqual(self.git(observer, "cat-file", "-t", claim["oid"]), "commit")
            claim_payload = json.loads(
                self.git(observer, "show", f"{claim['oid']}:claim.json")
            )
            self.assertEqual(claim_payload, readback["claim_payload"])
            self.assertEqual(
                claim_payload["capability_digest"],
                readback["capability_digest"],
            )
            self.assertEqual(
                claim_payload["invocation_id"],
                claim["invocation_id"],
            )
            self.assertEqual(
                self.remote_oid(observer, remote_url, "refs/heads/main"), commits[0]
            )
            self.assertEqual(
                self.remote_oid(observer, production.as_uri(), "refs/heads/main"),
                commits[0],
            )
            self.assertEqual(
                self.git(
                    observer,
                    "ls-remote",
                    "--refs",
                    production.as_uri(),
                    capability["claim_ref"],
                ),
                "",
            )

            replay = subprocess.run(
                command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(replay.returncode, 0)
            self.assertEqual(replay.stdout, "")

    def test_executor_rechecks_expiry_after_remote_reads_before_claim(self) -> None:
        expires_at = datetime(2026, 9, 1, 0, 0, 1, tzinfo=UTC)
        self._assert_expiry_blocks_provider_push(
            (expires_at,),
            expected_claim_writes=0,
        )

    def test_executor_rechecks_expiry_after_claim_mint_before_push(self) -> None:
        expires_at = datetime(2026, 9, 1, 0, 0, 1, tzinfo=UTC)
        self._assert_expiry_blocks_provider_push(
            (expires_at - timedelta(seconds=1), expires_at),
            expected_claim_writes=1,
        )

    def _assert_expiry_blocks_provider_push(
        self,
        now_values: tuple[datetime, ...],
        *,
        expected_claim_writes: int,
    ) -> None:
        expires_at = datetime(2026, 9, 1, 0, 0, 1, tzinfo=UTC)
        executor_private, executor_public = generate_keypair(bytes(range(32, 64)))
        expected_oid = "1" * 40
        desired_oid = "2" * 40
        namespace = "refs/heads/bdrive-candidate/expiry/"
        capability = {
            "transaction_id": "bd-control-expiry",
            "executor_id": "skret-candidate-executor-1",
            "executor_public_key": executor_public.hex(),
            "client_id": "better-drive-candidate-client-1",
            "remote": "n24q02m/synthetic-control",
            "remote_url_digest": "3" * 64,
            "ref_namespace": namespace,
            "claim_ref": namespace + "claim",
            "completion_ref": namespace + "completion",
            "operations": [
                {
                    "ref": namespace + "lease",
                    "expected_oid": expected_oid,
                    "desired_oid": desired_oid,
                }
            ],
            "ref_escape_probe": "refs/heads/main",
            "production_remote": "n24q02m/production-control",
            "production_ref": "refs/heads/main",
            "expires_at": self.timestamp(expires_at),
        }
        instants = iter(now_values)

        class ExpiredDateTime(datetime):
            @classmethod
            def now(cls, tz: object = None) -> datetime:
                return next(instants)

        class Provider:
            def __init__(self, *_: object) -> None:
                self.readbacks = iter((None, None, expected_oid))

            def read_optional(self, _remote: str, _ref: str) -> str | None:
                return next(self.readbacks)

            def push(self, _claim_oid: str) -> subprocess.CompletedProcess[str]:
                raise AssertionError("expired capability reached provider push")

        completed = subprocess.CompletedProcess(
            args=["git"],
            returncode=0,
            stdout="",
            stderr="",
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(control, "datetime", ExpiredDateTime),
            patch.object(control, "_run_git", return_value=completed),
            patch.object(control, "_prepare_scratch_repository"),
            patch.object(control, "_GitControlProvider", Provider),
            patch.object(
                control,
                "_write_local_claim_commit",
                return_value="4" * 40,
            ) as write_claim,
        ):
            with self.assertRaisesRegex(
                control.CandidateControlError,
                "capability is not currently valid",
            ):
                control.execute(
                    capability,
                    Path(temporary),
                    "file:///synthetic.git",
                    executor_private,
                    None,
                    "file-fixture",
                )
            self.assertEqual(write_claim.call_count, expected_claim_writes)

    @staticmethod
    def git(cwd: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return result.stdout.strip()

    def commit(self, repository: Path, index: int) -> str:
        (repository / "state.txt").write_text(f"state-{index}\n", encoding="utf-8")
        self.git(repository, "add", "state.txt")
        self.git(repository, "commit", "-m", f"state {index}")
        return self.git(repository, "rev-parse", "HEAD")

    def remote_oid(self, repository: Path, remote: str, ref: str) -> str:
        line = self.git(repository, "ls-remote", "--refs", remote, ref)
        oid, returned_ref = line.split("\t", 1)
        self.assertEqual(returned_ref, ref)
        return oid

    @staticmethod
    def timestamp(value: datetime) -> str:
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def digest(capability: dict[str, object]) -> str:
        unsigned = dict(capability)
        unsigned.pop("signature")
        return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


if __name__ == "__main__":
    unittest.main()
