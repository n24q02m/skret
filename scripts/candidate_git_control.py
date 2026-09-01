#!/usr/bin/env python3
"""Execute one signed, synthetic Git CAS capability and emit a signed readback."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from candidate_trust import (
    CandidateTrustError,
    canonical_json_bytes,
    parse_canonical_json,
    public_key_from_private,
    sign_bytes,
    verify_bytes,
)

CAPABILITY_PURPOSE = "BD-CANDIDATE-CONTROL-V1"
READBACK_PURPOSE = "BD-CANDIDATE-CONTROL-READBACK-V1"
MAX_INPUT_BYTES = 1 << 20
MAX_OPERATIONS = 16
MAX_VALIDITY = timedelta(minutes=15)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_OID = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]*$")
_REF_FORBIDDEN = re.compile(r"[ ~^:?*\[\\\x00\r\n\t]")


class CandidateControlError(ValueError):
    """Fail-closed candidate control error without credential values."""


def _fail(message: str) -> None:
    raise CandidateControlError(message)


def _read_regular(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    try:
        details = path.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size <= 0 or details.st_size > limit:
            _fail("candidate control input type or size is invalid")
        data = path.read_bytes()
    except OSError as exc:
        raise CandidateControlError("candidate control input is unreadable") from exc
    if not data or len(data) > limit:
        _fail("candidate control input type or size is invalid")
    return data


def _load_key(path: Path, *, private: bool) -> bytes:
    raw = _read_regular(path, 256)
    if len(raw) != 32:
        try:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise CandidateControlError("candidate control Ed25519 key is invalid") from exc
    if len(raw) != 32:
        _fail("candidate control Ed25519 key is invalid")
    if private and raw == b"\x00" * 32:
        _fail("candidate control private key is invalid")
    return raw


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail("candidate control timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CandidateControlError("candidate control timestamp is invalid") from exc
    if parsed.tzinfo is None:
        _fail("candidate control timestamp is invalid")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(f"candidate control {name} is invalid")
    return value


def _validate_repository(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.lower()
        or _REPOSITORY.fullmatch(value) is None
    ):
        _fail(f"candidate control {name} is invalid")
    return value


def _validate_ref(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("refs/")
        or len(value) > 255
        or _REF.fullmatch(value) is None
    ):
        _fail(f"candidate control {name} is invalid")
    if ".." in value or "@{" in value or value.endswith(".") or _REF_FORBIDDEN.search(value):
        _fail(f"candidate control {name} is invalid")
    parts = value.split("/")
    if any(not part or part in {".", ".."} or part.startswith(".") or part.endswith(".lock") for part in parts):
        _fail(f"candidate control {name} is invalid")
    return value


def _validate_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(f"candidate control {name} is invalid")
    return value


def _validate_oid(value: Any, name: str) -> str:
    if not isinstance(value, str) or _OID.fullmatch(value) is None:
        _fail(f"candidate control {name} is invalid")
    return value


def _unsigned_capability(capability: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in capability.items() if key != "signature"}


def _require_capability_current(capability: Mapping[str, Any]) -> datetime:
    now = datetime.now(UTC)
    if now >= _parse_timestamp(capability["expires_at"]):
        _fail("candidate control capability is not currently valid")
    return now


def _validate_capability(capability: Any, public_key: bytes, remote_url: str) -> dict[str, Any]:
    required = {
        "schema_version",
        "purpose",
        "transaction_id",
        "issuer",
        "executor_id",
        "executor_public_key",
        "client_id",
        "remote",
        "remote_url_digest",
        "ref_namespace",
        "claim_ref",
        "completion_ref",
        "operations",
        "operation_budget",
        "ref_escape_probe",
        "production_remote",
        "production_ref",
        "teardown_intent_digest",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    }
    if not isinstance(capability, dict) or set(capability) != required:
        _fail("candidate control capability shape is invalid")
    if capability["schema_version"] != 1 or capability["purpose"] != CAPABILITY_PURPOSE:
        _fail("candidate control capability schema or purpose is invalid")
    for name in ("transaction_id", "issuer", "executor_id", "client_id", "nonce"):
        _validate_id(capability[name], name)
    _validate_digest(capability["executor_public_key"], "executor public key")
    remote = _validate_repository(capability["remote"], "remote")
    production_remote = _validate_repository(capability["production_remote"], "production remote")
    if remote == production_remote:
        _fail("candidate control synthetic and production remotes must differ")
    _validate_digest(capability["remote_url_digest"], "remote URL digest")
    if hashlib.sha256(remote_url.encode("utf-8")).hexdigest() != capability["remote_url_digest"]:
        _fail("candidate control remote URL digest mismatch")
    namespace = capability["ref_namespace"]
    if (
        not isinstance(namespace, str)
        or not namespace.startswith("refs/heads/")
        or not namespace.endswith("/")
    ):
        _fail("candidate control ref namespace is invalid")
    _validate_ref(namespace[:-1], "ref namespace")
    claim_ref = _validate_ref(capability["claim_ref"], "claim ref")
    completion_ref = _validate_ref(capability["completion_ref"], "completion ref")
    if (
        not claim_ref.startswith(namespace)
        or not completion_ref.startswith(namespace)
        or claim_ref == completion_ref
    ):
        _fail("candidate control claim or completion binding is invalid")
    escape_ref = _validate_ref(capability["ref_escape_probe"], "ref escape probe")
    production_ref = _validate_ref(capability["production_ref"], "production ref")
    if escape_ref.startswith(namespace) or production_ref.startswith(namespace):
        _fail("candidate control denial probe overlaps the allowed namespace")
    operations = capability["operations"]
    if not isinstance(operations, list) or not operations or len(operations) > MAX_OPERATIONS:
        _fail("candidate control operations are invalid")
    if capability["operation_budget"] != len(operations):
        _fail("candidate control operation budget is not exact")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != {"ref", "expected_oid", "desired_oid"}:
            _fail("candidate control operation shape is invalid")
        ref = _validate_ref(operation["ref"], "operation ref")
        expected = _validate_oid(operation["expected_oid"], "expected OID")
        desired = _validate_oid(operation["desired_oid"], "desired OID")
        if not ref.startswith(namespace):
            _fail("candidate control operation ref escapes the namespace")
        if ref in seen or ref in {claim_ref, completion_ref} or expected == desired:
            _fail("candidate control operation is duplicate or unchanged")
        seen.add(ref)
        normalized.append({"ref": ref, "expected_oid": expected, "desired_oid": desired})
    normalized.sort(key=lambda item: item["ref"])
    if normalized != operations:
        _fail("candidate control operations must be sorted by ref")
    _validate_digest(capability["teardown_intent_digest"], "teardown intent digest")
    issued_at = _parse_timestamp(capability["issued_at"])
    expires_at = _parse_timestamp(capability["expires_at"])
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY:
        _fail("candidate control validity interval is invalid")
    now = _require_capability_current(capability)
    if issued_at > now + timedelta(minutes=1):
        _fail("candidate control capability is not currently valid")
    signature = capability["signature"]
    if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
        _fail("candidate control capability signature is invalid")
    try:
        signature_bytes = bytes.fromhex(signature)
    except ValueError as exc:
        raise CandidateControlError("candidate control capability signature is invalid") from exc
    if not verify_bytes(canonical_json_bytes(_unsigned_capability(capability)), signature_bytes, public_key):
        _fail("candidate control capability signature verification failed")
    result = dict(capability)
    result["operations"] = normalized
    return result


def _validate_remote_url(
    remote_url: str,
    token_path: Path | None,
    expected_remote: str,
    *,
    allow_file_fixture: bool,
) -> str:
    try:
        parsed = urlsplit(remote_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise CandidateControlError(
            "candidate control remote URL is invalid"
        ) from exc
    if parsed.scheme == "file":
        if (
            not allow_file_fixture
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or token_path is not None
        ):
            _fail("candidate control file fixture remote URL is invalid")
        return "file-fixture"
    if parsed.scheme == "https":
        expected_url = f"https://github.com/{expected_remote}.git"
        if (
            remote_url != expected_url
            or parsed.netloc != "github.com"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or token_path is None
        ):
            _fail("candidate control GitHub remote identity or token route is invalid")
        return "github"
    _fail("candidate control remote scheme is unsupported")


def _git_environment(home: Path, token_path: Path | None) -> dict[str, str]:
    allowed = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    global_config = home / "gitconfig"
    global_config.write_text("", encoding="utf-8")
    environment.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    if token_path is not None:
        if os.name == "nt":
            _fail("candidate control HTTPS token route requires the Linux executor")
        token = _read_regular(token_path, 64 * 1024)
        if b"\x00" in token or b"\r" in token or b"\n" in token or not token.strip():
            _fail("candidate control Git token file is invalid")
        askpass = home / "git-askpass.py"
        askpass.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "prompt = sys.argv[1] if len(sys.argv) > 1 else ''\n"
            "if 'Username' in prompt:\n"
            "    print('x-access-token')\n"
            "else:\n"
            "    sys.stdout.write(pathlib.Path(os.environ['SKRET_GIT_TOKEN_FILE']).read_text(encoding='utf-8').strip())\n",
            encoding="utf-8",
        )
        askpass.chmod(0o700)
        environment.update(
            {
                "GIT_ASKPASS": str(askpass),
                "GIT_ASKPASS_REQUIRE": "force",
                "SKRET_GIT_TOKEN_FILE": str(token_path),
            }
        )
    return environment


def _run_git(repository: Path, environment: Mapping[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if len(result.stdout) > MAX_INPUT_BYTES or len(result.stderr) > MAX_INPUT_BYTES:
        _fail("candidate control Git output is oversized")
    return result


def _remote_oid_optional(
    repository: Path,
    environment: Mapping[str, str],
    remote_url: str,
    ref: str,
) -> str | None:
    result = _run_git(repository, environment, "ls-remote", "--refs", remote_url, ref)
    if result.returncode != 0:
        _fail("candidate control remote readback failed")
    lines = [line for line in result.stdout.splitlines() if line]
    if not lines:
        return None
    if len(lines) != 1:
        _fail("candidate control remote ref is ambiguous")
    try:
        oid, returned_ref = lines[0].split("\t", 1)
    except ValueError as exc:
        raise CandidateControlError("candidate control remote readback is invalid") from exc
    if returned_ref != ref:
        _fail("candidate control remote readback returned the wrong ref")
    return _validate_oid(oid, "remote readback OID")


def _push_arguments(
    capability: Mapping[str, Any],
    remote_url: str,
    claim_oid: str,
) -> list[str]:
    arguments = [
        "push",
        "--porcelain",
        "--atomic",
        f"--force-with-lease={capability['claim_ref']}:",
        f"--force-with-lease={capability['completion_ref']}:",
    ]
    for operation in capability["operations"]:
        arguments.append(
            f"--force-with-lease={operation['ref']}:{operation['expected_oid']}"
        )
    arguments.append(remote_url)
    arguments.extend(
        (
            f"{claim_oid}:{capability['claim_ref']}",
            f"{claim_oid}:{capability['completion_ref']}",
        )
    )
    arguments.extend(
        f"{operation['desired_oid']}:{operation['ref']}"
        for operation in capability["operations"]
    )
    return arguments


def _authorize_target(
    capability: Mapping[str, Any],
    remote: str,
    ref: str,
) -> str:
    if remote != capability["remote"]:
        return "REMOTE_OUTSIDE_ALLOWLIST"
    if not ref.startswith(capability["ref_namespace"]):
        return "REF_OUTSIDE_NAMESPACE"
    return "ALLOWED"


def _claim_payload_record(
    capability: Mapping[str, Any],
    capability_digest: str,
    invocation_id: str,
    claimed_at: datetime,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "purpose": "BD-CANDIDATE-CONTROL-CLAIM-V1",
        "transaction_id": capability["transaction_id"],
        "capability_digest": capability_digest,
        "executor_id": capability["executor_id"],
        "executor_public_key": capability["executor_public_key"],
        "invocation_id": invocation_id,
        "claimed_at": _timestamp(claimed_at),
    }


def _atomic_updates(
    capability: Mapping[str, Any],
    requested_claim_oid: str,
    observed_claim_before: str | None,
    observed_claim_after: str,
    operation_before: Sequence[str],
    operation_after: Sequence[str],
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = [
        {
            "kind": "claim",
            "ref": capability["claim_ref"],
            "expected_oid": None,
            "desired_oid": requested_claim_oid,
            "before_oid": observed_claim_before,
            "after_oid": observed_claim_after,
        }
    ]
    updates.extend(
        {
            "kind": "operation",
            "ref": operation["ref"],
            "expected_oid": operation["expected_oid"],
            "desired_oid": operation["desired_oid"],
            "before_oid": before,
            "after_oid": after,
        }
        for operation, before, after in zip(
            capability["operations"],
            operation_before,
            operation_after,
            strict=True,
        )
    )
    updates.append(
        {
            "kind": "completion",
            "ref": capability["completion_ref"],
            "expected_oid": None,
            "desired_oid": requested_claim_oid,
            "before_oid": observed_claim_before,
            "after_oid": observed_claim_after,
        }
    )
    return updates


def _write_local_claim_commit(
    repository: Path,
    environment: Mapping[str, str],
    data: bytes,
) -> str:
    def write_object(
        arguments: Sequence[str],
        input_data: bytes,
        *,
        command_environment: Mapping[str, str] | None = None,
    ) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            env=dict(command_environment or environment),
            input=input_data,
            check=False,
            capture_output=True,
            timeout=60,
        )
        if (
            result.returncode != 0
            or len(result.stdout) > MAX_INPUT_BYTES
            or len(result.stderr) > MAX_INPUT_BYTES
        ):
            _fail("candidate control local claim commit write failed")
        try:
            oid = result.stdout.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise CandidateControlError(
                "candidate control local claim commit OID is invalid"
            ) from exc
        return _validate_oid(oid, "local claim commit OID")

    blob_oid = write_object(("hash-object", "-w", "--stdin"), data)
    tree_oid = write_object(
        ("mktree",),
        f"100644 blob {blob_oid}\tclaim.json\n".encode("ascii"),
    )
    commit_environment = dict(environment)
    commit_environment.update(
        {
            "GIT_AUTHOR_NAME": "Skret Candidate Executor",
            "GIT_AUTHOR_EMAIL": "candidate-executor@example.invalid",
            "GIT_AUTHOR_DATE": "@0 +0000",
            "GIT_COMMITTER_NAME": "Skret Candidate Executor",
            "GIT_COMMITTER_EMAIL": "candidate-executor@example.invalid",
            "GIT_COMMITTER_DATE": "@0 +0000",
        }
    )
    return write_object(
        ("commit-tree", tree_oid),
        b"candidate control claim\n",
        command_environment=commit_environment,
    )

def _prepare_scratch_repository(
    source: Path,
    scratch: Path,
    environment: Mapping[str, str],
    desired_oids: Sequence[str],
) -> None:
    source_path = source.resolve(strict=True)
    scratch.mkdir(mode=0o700)
    initialized = _run_git(scratch, environment, "init", "--quiet")
    if initialized.returncode != 0:
        _fail("candidate control scratch repository initialization failed")
    for oid in sorted(set(desired_oids)):
        fetched = _run_git(
            scratch,
            environment,
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            str(source_path),
            oid,
        )
        if fetched.returncode != 0:
            _fail("candidate control bound commit import failed")
        verified = _run_git(
            scratch,
            environment,
            "cat-file",
            "-e",
            f"{oid}^{{commit}}",
        )
        if verified.returncode != 0:
            _fail("candidate control bound commit is absent from scratch repository")





class _GitControlProvider:
    def __init__(
        self,
        capability: Mapping[str, Any],
        repository: Path,
        remote_url: str,
        environment: Mapping[str, str],
        token_path: Path | None,
    ) -> None:
        self.capability = capability
        self.repository = repository
        self.remote_url = remote_url
        self.environment = environment
        self.scheme = urlsplit(remote_url).scheme
        self.calls = 0
        self.token: str | None = None
        if token_path is not None:
            try:
                self.token = _read_regular(token_path, 64 * 1024).decode(
                    "utf-8", errors="strict"
                ).strip()
            except UnicodeError as exc:
                raise CandidateControlError(
                    "candidate control Git token file is invalid"
                ) from exc
            if not self.token:
                _fail("candidate control Git token file is invalid")

    def _require_allowed(self, remote: str, ref: str) -> None:
        outcome = _authorize_target(self.capability, remote, ref)
        if outcome != "ALLOWED":
            raise CandidateControlError(outcome)

    def denial_probe(self, remote: str, ref: str) -> dict[str, Any]:
        before = self.calls
        outcome = _authorize_target(self.capability, remote, ref)
        if outcome == "ALLOWED":
            _fail("candidate control denial probe unexpectedly passed authorization")
        after = self.calls
        if after != before:
            _fail("candidate control denial probe reached the provider")
        return {
            "remote": remote,
            "ref": ref,
            "provider_invoked": after != before,
            "provider_calls_before": before,
            "provider_calls_after": after,
            "outcome": outcome,
        }

    def read_optional(self, remote: str, ref: str) -> str | None:
        self._require_allowed(remote, ref)
        self.calls += 1
        return _remote_oid_optional(
            self.repository,
            self.environment,
            self.remote_url,
            ref,
        )







    def push(self, claim_oid: str) -> subprocess.CompletedProcess[str]:
        for ref in (
            self.capability["claim_ref"],
            self.capability["completion_ref"],
            *(operation["ref"] for operation in self.capability["operations"]),
        ):
            self._require_allowed(self.capability["remote"], ref)
        self.calls += 1
        return _run_git(
            self.repository,
            self.environment,
            *_push_arguments(self.capability, self.remote_url, claim_oid),
        )

    def completed_replay_probe(
        self,
        winning_claim_oid: str,
        replay_claim_oid: str,
    ) -> dict[str, Any]:
        remote = self.capability["remote"]
        before_calls = self.calls
        before_claim = self.read_optional(remote, self.capability["claim_ref"])
        before_completion = self.read_optional(
            remote,
            self.capability["completion_ref"],
        )
        before_operations = [
            {
                "ref": operation["ref"],
                "oid": self.read_optional(remote, operation["ref"]),
            }
            for operation in self.capability["operations"]
        ]
        replay = self.push(replay_claim_oid)
        after_claim = self.read_optional(remote, self.capability["claim_ref"])
        after_completion = self.read_optional(
            remote,
            self.capability["completion_ref"],
        )
        after_operations = [
            {
                "ref": operation["ref"],
                "oid": self.read_optional(remote, operation["ref"]),
            }
            for operation in self.capability["operations"]
        ]
        expected_operations = [
            {
                "ref": operation["ref"],
                "oid": operation["desired_oid"],
            }
            for operation in self.capability["operations"]
        ]
        if replay.returncode == 0:
            _fail("candidate control replay unexpectedly succeeded")
        if (
            before_claim != winning_claim_oid
            or after_claim != winning_claim_oid
            or before_completion != winning_claim_oid
            or after_completion != winning_claim_oid
            or before_operations != expected_operations
            or after_operations != expected_operations
        ):
            _fail("candidate control replay denial changed bound state")
        return {
            "attempted": True,
            "provider_invoked": True,
            "provider_calls_before": before_calls,
            "provider_calls_after": self.calls,
            "exit_code": replay.returncode,
            "winning_claim_oid": winning_claim_oid,
            "attempted_claim_oid": replay_claim_oid,
            "outcome": "ALREADY_COMPLETED",
            "claim_oid_before": before_claim,
            "claim_oid_after": after_claim,
            "completion_oid_before": before_completion,
            "completion_oid_after": after_completion,
            "operations_before": before_operations,
            "operations_after": after_operations,
        }


def execute(
    capability: Mapping[str, Any],
    repository: Path,
    remote_url: str,
    executor_private_key: bytes,
    token_path: Path | None,
    transport: str,
) -> dict[str, Any]:
    try:
        expected_executor_key = bytes.fromhex(capability["executor_public_key"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CandidateControlError(
            "candidate control executor public key is invalid"
        ) from exc
    if public_key_from_private(executor_private_key) != expected_executor_key:
        _fail("candidate control executor private key does not match the capability")
    capability_digest = hashlib.sha256(
        canonical_json_bytes(_unsigned_capability(capability))
    ).hexdigest()

    with tempfile.TemporaryDirectory(prefix="skret-candidate-git-") as temporary:
        temporary_path = Path(temporary)
        environment = _git_environment(temporary_path, token_path)
        probe = _run_git(repository, environment, "rev-parse", "--git-dir")
        if probe.returncode != 0:
            _fail("candidate control local repository is invalid")
        scratch_repository = temporary_path / "provider-repository"
        _prepare_scratch_repository(
            repository,
            scratch_repository,
            environment,
            [
                operation["desired_oid"]
                for operation in capability["operations"]
            ],
        )

        provider = _GitControlProvider(
            capability,
            scratch_repository,
            remote_url,
            environment,
            token_path,
        )
        remote = capability["remote"]
        completion_before = provider.read_optional(
            remote,
            capability["completion_ref"],
        )
        claim_before = provider.read_optional(remote, capability["claim_ref"])
        operation_before = [
            provider.read_optional(remote, operation["ref"])
            for operation in capability["operations"]
        ]
        desired_oids = [
            operation["desired_oid"] for operation in capability["operations"]
        ]
        expected_oids = [
            operation["expected_oid"] for operation in capability["operations"]
        ]
        if claim_before is not None or completion_before is not None:
            if (
                claim_before is not None
                and claim_before == completion_before
                and operation_before == desired_oids
            ):
                _fail("candidate control transaction is already completed")
            _fail("candidate control transaction has existing inconsistent state")
        if operation_before != expected_oids:
            _fail("candidate control CAS precondition failed")

        claim_time = _require_capability_current(capability)
        invocation_id = secrets.token_hex(16)
        claim_payload_record = _claim_payload_record(
            capability,
            capability_digest,
            invocation_id,
            claim_time,
        )
        claim_payload = canonical_json_bytes(claim_payload_record)
        claim_oid = _write_local_claim_commit(
            scratch_repository,
            environment,
            claim_payload,
        )
        _require_capability_current(capability)
        push = provider.push(claim_oid)
        claim_after = provider.read_optional(remote, capability["claim_ref"])
        completion_after = provider.read_optional(
            remote,
            capability["completion_ref"],
        )
        current_oids = [
            provider.read_optional(remote, operation["ref"])
            for operation in capability["operations"]
        ]
        if (
            claim_after != claim_oid
            or completion_after != claim_oid
            or current_oids != desired_oids
        ):
            if push.returncode == 0:
                _fail("candidate control atomic push readback mismatch")
            _fail("candidate control atomic CAS was denied or incomplete")

        operation_readbacks = [
            {
                "ref": operation["ref"],
                "expected_oid": operation["expected_oid"],
                "desired_oid": operation["desired_oid"],
                "before_oid": operation["expected_oid"],
                "after_oid": current,
            }
            for operation, current in zip(
                capability["operations"],
                current_oids,
                strict=True,
            )
        ]
        replay_invocation_id = secrets.token_hex(16)
        replay_claim_payload_record = _claim_payload_record(
            capability,
            capability_digest,
            replay_invocation_id,
            datetime.now(UTC),
        )
        replay_claim_oid = _write_local_claim_commit(
            scratch_repository,
            environment,
            canonical_json_bytes(replay_claim_payload_record),
        )
        replay_probe = provider.completed_replay_probe(
            claim_oid,
            replay_claim_oid,
        )
        replay_probe.update(
            {
                "attempted_invocation_id": replay_invocation_id,
                "attempted_claim_payload": replay_claim_payload_record,
                "updates": _atomic_updates(
                    capability,
                    replay_claim_oid,
                    claim_oid,
                    claim_oid,
                    desired_oids,
                    desired_oids,
                ),
            }
        )
        ref_escape_probe = provider.denial_probe(
            remote,
            capability["ref_escape_probe"],
        )
        production_remote_probe = provider.denial_probe(
            capability["production_remote"],
            capability["production_ref"],
        )
        production_ref_probe = provider.denial_probe(
            remote,
            capability["production_ref"],
        )

    unsigned = {
        "schema_version": 1,
        "purpose": READBACK_PURPOSE,
        "transaction_id": capability["transaction_id"],
        "capability_digest": capability_digest,
        "issuer": capability["executor_id"],
        "executor_id": capability["executor_id"],
        "client_id": capability["client_id"],
        "remote": capability["remote"],
        "remote_url_digest": capability["remote_url_digest"],
        "transport": transport,
        "claim_payload": claim_payload_record,
        "claim": {
            "ref": capability["claim_ref"],
            "oid": claim_oid,
            "invocation_id": invocation_id,
            "created": True,
        },
        "completion": {
            "ref": capability["completion_ref"],
            "oid": claim_oid,
            "invocation_id": invocation_id,
            "created": True,
        },
        "operations": operation_readbacks,
        "operation_count": len(operation_readbacks),
        "atomic_push": {
            "attempted": True,
            "exit_code": push.returncode,
            "reconciled": push.returncode != 0,
            "updates": _atomic_updates(
                capability,
                claim_oid,
                None,
                claim_oid,
                expected_oids,
                current_oids,
            ),
        },
        "replay_probe": replay_probe,
        "ref_escape_probe": ref_escape_probe,
        "production_remote_probe": production_remote_probe,
        "production_ref_probe": production_ref_probe,
        "observed_at": _timestamp(datetime.now(UTC)),
    }
    return {
        **unsigned,
        "signature": sign_bytes(
            canonical_json_bytes(unsigned),
            executor_private_key,
        ).hex(),
    }



def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="candidate_git_control.py")
    parser.add_argument("--capability", required=True)
    parser.add_argument("--issuer-public-key", required=True)
    parser.add_argument("--executor-private-key", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--remote-url", required=True)
    parser.add_argument("--git-token-file")
    parser.add_argument(
        "--allow-file-fixture",
        action="store_true",
        help="allow a local file:// remote for isolated contract tests only",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        capability_raw = _read_regular(Path(arguments.capability))
        if capability_raw.endswith(b"\n"):
            capability_raw = capability_raw[:-1]
        capability = parse_canonical_json(capability_raw)
        issuer_public_key = _load_key(Path(arguments.issuer_public_key), private=False)
        executor_private_key = _load_key(Path(arguments.executor_private_key), private=True)
        token_path = Path(arguments.git_token_file) if arguments.git_token_file else None
        verified = _validate_capability(
            capability,
            issuer_public_key,
            arguments.remote_url,
        )
        transport = _validate_remote_url(
            arguments.remote_url,
            token_path,
            verified["remote"],
            allow_file_fixture=arguments.allow_file_fixture,
        )
        result = execute(
            verified,
            Path(arguments.repository),
            arguments.remote_url,
            executor_private_key,
            token_path,
            transport,
        )
        sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
        return 0
    except (CandidateControlError, CandidateTrustError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
