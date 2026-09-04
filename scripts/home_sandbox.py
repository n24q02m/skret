#!/usr/bin/env python3
"""Run exact Skret candidates in an isolated Home-compatible sandbox."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, NamedTuple, Protocol, Sequence

SCHEMA = "skret-home-sandbox/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_STAGED_STATE_DIRECTORY = "synthetic-state"
_SPEC_FIELDS = {
    "schema",
    "candidate_binary",
    "candidate_digest",
    "candidate_version",
    "live_binary",
    "live_config_paths",
    "synthetic_config",
    "synthetic_values",
    "sentinel_program",
    "synthetic_state_root",
    "state_file",
    "state_manifest",
    "state_public_key",
    "sandbox_root",
}
_MANIFEST_EXPIRY = re.compile(
    r"^(?P<second>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_MANIFEST_MAX_TTL = timedelta(minutes=15)
_CANDIDATE_TRUST_MODULE: Any | None = None
_ALLOWED_ENV = ("PATH", "SystemRoot", "WINDIR")


class HomeSandboxError(RuntimeError):
    """A value-free sandbox validation or execution failure."""


class CommandResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def run(self, argv: list[str], env: dict[str, str], cwd: str) -> CommandResult: ...


class SubprocessRunner:
    def run(self, argv: list[str], env: dict[str, str], cwd: str) -> CommandResult:
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=cwd,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HomeSandboxError("sandbox command unavailable") from exc
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _fail(message: str = "invalid Home sandbox request") -> None:
    raise HomeSandboxError(message)


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HomeSandboxError("invalid Home sandbox JSON") from exc


def parse_spec(data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="strict")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        _fail()
    if not raw or b"\r" in raw:
        _fail()
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except HomeSandboxError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HomeSandboxError("invalid Home sandbox JSON") from exc
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != raw:
        _fail()
    _validate_spec(parsed)
    return parsed


def _is_reparse(details: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(details, "st_file_attributes", 0) & marker)


def _absolute_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail()
    if any(component in {".", ".."} for component in re.split(r"[\\/]", value)):
        _fail()
    path = Path(value)
    if not path.is_absolute():
        _fail()
    return path


def _normalized_path(path: Path) -> Path:
    return Path(os.path.abspath(os.path.normpath(path)))


def _strict_relative(path: Path, root: Path) -> Path:
    try:
        relative = _normalized_path(path).relative_to(_normalized_path(root))
    except ValueError:
        _fail()
    if relative == Path(".") or any(component in {".", ".."} for component in relative.parts):
        _fail()
    return relative


def _regular_path(value: Any) -> Path:
    path = _absolute_path(value)
    try:
        details = os.lstat(path)
    except OSError as exc:
        raise HomeSandboxError("sandbox input unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISREG(details.st_mode):
        _fail()
    return path


def _regular_directory(value: Any) -> Path:
    path = _absolute_path(value)
    try:
        details = os.lstat(path)
    except OSError as exc:
        raise HomeSandboxError("sandbox input unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
        _fail()
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        _normalized_path(path).relative_to(_normalized_path(root))
    except ValueError:
        return False
    return True


def _candidate_trust_module() -> Any:
    global _CANDIDATE_TRUST_MODULE
    if _CANDIDATE_TRUST_MODULE is not None:
        return _CANDIDATE_TRUST_MODULE
    module_path = Path(__file__).resolve().with_name("candidate_trust.py")
    module_spec = importlib.util.spec_from_file_location("_skret_candidate_trust", module_path)
    if module_spec is None or module_spec.loader is None:
        _fail("candidate trust implementation unavailable")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    _CANDIDATE_TRUST_MODULE = module
    return module


def _go_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HomeSandboxError("invalid state manifest JSON") from exc
    return (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
        .encode("utf-8", errors="strict")
    )


def _canonical_manifest_expiry(value: Any) -> tuple[str, datetime]:
    if not isinstance(value, str):
        _fail()
    match = _MANIFEST_EXPIRY.fullmatch(value)
    if match is None:
        _fail()
    fraction = match.group("fraction") or ""
    microseconds = int((fraction[:6]).ljust(6, "0")) if fraction else 0
    try:
        expiry = datetime.strptime(match.group("second"), "%Y-%m-%dT%H:%M:%S").replace(
            microsecond=microseconds,
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise HomeSandboxError("invalid synthetic state manifest") from exc
    canonical_fraction = fraction.rstrip("0")
    canonical = match.group("second")
    if canonical_fraction:
        canonical += "." + canonical_fraction
    return canonical + "Z", expiry


def _read_public_key(path: Path) -> bytes:
    try:
        encoded = path.read_bytes()
        if len(encoded) == 32:
            return encoded
        decoded = bytes.fromhex(encoded.decode("ascii").strip())
    except (OSError, UnicodeError, ValueError) as exc:
        raise HomeSandboxError("invalid synthetic state public key") from exc
    if len(decoded) != 32:
        _fail()
    return decoded


def _verify_state_manifest(
    manifest_path: Path,
    public_key_path: Path,
    expected_source_root: Path,
    state_path: Path,
    state_relative: str,
) -> dict[str, Any]:
    try:
        document = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HomeSandboxError("invalid synthetic state manifest") from exc
    if not isinstance(document, dict) or set(document) != {
        "version",
        "role",
        "audience",
        "source_root",
        "files",
        "nonce",
        "expires_at",
        "signature",
    }:
        _fail()
    files = document.get("files")
    if (
        type(document.get("version")) is not int
        or document["version"] != 1
        or document.get("role") != "operator"
        or document.get("audience") != "hub"
        or not isinstance(document.get("nonce"), str)
        or not document["nonce"].strip()
        or "\x00" in document["nonce"]
        or not isinstance(document.get("source_root"), str)
        or Path(document["source_root"]) != expected_source_root
        or document["source_root"] != str(expected_source_root)
        or not isinstance(files, list)
        or len(files) != 1
    ):
        _fail()
    row = files[0]
    state_digest = _digest_file(state_path).removeprefix("sha256:")
    state_size = os.lstat(state_path).st_size
    if (
        not isinstance(row, dict)
        or set(row) != {"path", "size", "sha256"}
        or row.get("path") != state_relative
        or type(row.get("size")) is not int
        or row.get("size") != state_size
        or row.get("sha256") != state_digest
    ):
        _fail()
    canonical_expiry, expiry = _canonical_manifest_expiry(document.get("expires_at"))
    now = datetime.now(timezone.utc)
    if expiry <= now or expiry - now > _MANIFEST_MAX_TTL:
        _fail()
    signature_text = document.get("signature")
    if not isinstance(signature_text, str) or len(signature_text) != 88 or not signature_text.endswith("=="):
        _fail()
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except ValueError as exc:
        raise HomeSandboxError("invalid synthetic state manifest") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
        _fail()
    signing_document = {
        "version": document["version"],
        "role": document["role"],
        "audience": document["audience"],
        "source_root": document["source_root"],
        "files": [
            {
                "path": row["path"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
        ],
        "nonce": document["nonce"],
        "expires_at": canonical_expiry,
    }
    public_key = _read_public_key(public_key_path)
    trust = _candidate_trust_module()
    if not trust.verify_bytes(_go_json_bytes(signing_document), signature, public_key):
        _fail()
    actual_files = {
        entry["path"]: entry
        for entry in _directory_snapshot(expected_source_root)
        if entry["kind"] == "file"
        and entry["path"] not in {"state-manifest.json", "state-public-key"}
    }
    if set(actual_files) != {state_relative}:
        _fail()
    source_state = expected_source_root.joinpath(*state_relative.split("/"))
    if not _is_within(source_state, expected_source_root):
        _fail()
    try:
        source_size = os.lstat(source_state).st_size
    except OSError as exc:
        raise HomeSandboxError("synthetic state changed during verification") from exc
    if (
        source_size != row["size"]
        or actual_files[state_relative]["digest"] != "sha256:" + row["sha256"]
    ):
        _fail()
    return signing_document


def _validate_synthetic_state_root(
    state_root: Path,
    state_file: Path,
    state_manifest: Path,
    state_public_key: Path,
) -> None:
    if any(not _is_within(path, state_root) for path in (state_file, state_manifest, state_public_key)):
        _fail()
    if (
        state_manifest.parent != state_root
        or state_manifest.name != "state-manifest.json"
        or state_public_key.parent != state_root
        or state_public_key.name != "state-public-key"
    ):
        _fail()
    state_relative = _strict_relative(state_file, state_root).as_posix()
    _verify_state_manifest(
        state_manifest,
        state_public_key,
        state_root,
        state_file,
        state_relative,
    )


def _new_sandbox_path(value: Any) -> Path:
    path = _absolute_path(value)
    if path.exists() or path.is_symlink():
        _fail()
    return path


def _validate_spec(spec: Mapping[str, Any]) -> None:
    if set(spec) != _SPEC_FIELDS or spec.get("schema") != SCHEMA:
        _fail()
    if not isinstance(spec.get("candidate_digest"), str) or _DIGEST.fullmatch(spec["candidate_digest"]) is None:
        _fail()
    if not isinstance(spec.get("candidate_version"), str) or _VERSION.fullmatch(spec["candidate_version"]) is None:
        _fail()
    live_configs = spec.get("live_config_paths")
    if not isinstance(live_configs, list) or not live_configs or live_configs != sorted(set(live_configs)):
        _fail()
    candidate = _regular_path(spec.get("candidate_binary"))
    live_binary = _regular_path(spec.get("live_binary"))
    sandbox = _new_sandbox_path(spec.get("sandbox_root"))
    state_root = _regular_directory(spec.get("synthetic_state_root"))
    state_file = _regular_path(spec.get("state_file"))
    state_manifest = _regular_path(spec.get("state_manifest"))
    state_public_key = _regular_path(spec.get("state_public_key"))
    _validate_synthetic_state_root(
        state_root,
        state_file,
        state_manifest,
        state_public_key,
    )
    input_roles = [
        candidate,
        live_binary,
        *(_regular_path(path) for path in live_configs),
        _regular_path(spec.get("synthetic_config")),
        _regular_path(spec.get("synthetic_values")),
        _regular_path(spec.get("sentinel_program")),
    ]
    # state files are already validated as within state_root; check disjointness separately
    inputs: list[Path] = []
    for source in input_roles:
        if source in inputs:
            _fail()
        inputs.append(source)
        if _is_within(source, state_root) or _is_within(state_root, source):
            _fail()
    if candidate == live_binary:
        _fail()
    if _is_within(sandbox, state_root) or _is_within(state_root, sandbox):
        _fail()
    for source in inputs:
        if _is_within(sandbox, source) or _is_within(source, sandbox):
            _fail()
    # live configs must not be inside synthetic state root
    for cfg in live_configs:
        cfg_path = Path(cfg)
        if _is_within(cfg_path, state_root) or _is_within(state_root, cfg_path):
            _fail()

def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            _fail()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                _fail("sandbox input changed")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            path_after = os.lstat(path)
            if (
                (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
                or opened.st_size != after.st_size
                or getattr(opened, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
            ):
                _fail("sandbox input changed")
        finally:
            os.close(descriptor)
    except HomeSandboxError:
        raise
    except OSError as exc:
        raise HomeSandboxError("sandbox input unavailable") from exc
    return "sha256:" + digest.hexdigest()


def _copy_regular(source: Path, destination: Path, mode: int = 0o600) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        _fail("sandbox destination conflict")
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    success = False
    try:
        before = os.lstat(source)
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            _fail("unsafe sandbox input")
        source_descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(source_descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            _fail("sandbox input changed")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            mode,
        )
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError("short sandbox write")
                offset += written
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        path_after = os.lstat(source)
        if (
            (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
            or opened.st_size != after.st_size
            or getattr(opened, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
        ):
            _fail("sandbox input changed")
        os.chmod(destination, mode)
        success = True
    except HomeSandboxError:
        raise
    except OSError as exc:
        raise HomeSandboxError("sandbox copy failed") from exc
    finally:
        for descriptor in (source_descriptor, destination_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if not success:
            try:
                destination.unlink()
            except OSError:
                pass


def _write_new_file(destination: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor: int | None = None
    success = False
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            mode,
        )
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short sandbox write")
            offset += written
        os.fsync(descriptor)
        os.chmod(destination, mode)
        success = True
    except OSError as exc:
        raise HomeSandboxError("sandbox write failed") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not success:
            try:
                destination.unlink()
            except OSError:
                pass


def _create_staged_state_manifest(
    source_manifest: Path,
    source_public_key: Path,
    source_root: Path,
    staged_root: Path,
    staged_state: Path,
    staged_manifest: Path,
    staged_public_key: Path,
) -> None:
    state_relative = staged_state.relative_to(staged_root).as_posix()
    source_document = _verify_state_manifest(
        source_manifest,
        source_public_key,
        source_root,
        staged_state,
        state_relative,
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    source_expiry_text, source_expiry = _canonical_manifest_expiry(source_document["expires_at"])
    local_expiry = now + timedelta(minutes=5)
    staged_expiry = (
        source_expiry_text
        if source_expiry <= local_expiry
        else local_expiry.isoformat().replace("+00:00", "Z")
    )
    signing_document = {
        "version": source_document["version"],
        "role": source_document["role"],
        "audience": source_document["audience"],
        "source_root": str(staged_root),
        "files": [
            {
                "path": state_relative,
                "size": os.lstat(staged_state).st_size,
                "sha256": _digest_file(staged_state).removeprefix("sha256:"),
            }
        ],
        "nonce": "home-sandbox-" + os.urandom(16).hex(),
        "expires_at": staged_expiry,
    }
    trust = _candidate_trust_module()
    private_key, public_key = trust.generate_keypair()
    signature = trust.sign_bytes(_go_json_bytes(signing_document), private_key)
    staged_document = dict(signing_document)
    staged_document["signature"] = base64.b64encode(signature).decode("ascii")
    _write_new_file(staged_manifest, _go_json_bytes(staged_document))
    _write_new_file(staged_public_key, public_key)
    _verify_state_manifest(
        staged_manifest,
        staged_public_key,
        staged_root,
        staged_state,
        state_relative,
    )


def _clean_environment(sandbox: Path) -> dict[str, str]:
    home = sandbox / "home"
    temporary = sandbox / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = {name: os.environ[name] for name in _ALLOWED_ENV if name in os.environ}
    environment.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TEMP": str(temporary),
        "TMP": str(temporary),
    })
    return environment


def _run_checked(
    runner: CommandRunner,
    argv: list[str],
    environment: dict[str, str],
    cwd: Path,
) -> CommandResult:
    if not argv or any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
        _fail("invalid sandbox command")
    result = runner.run(argv, dict(environment), str(cwd))
    if not isinstance(result, CommandResult) or result.returncode != 0:
        raise HomeSandboxError("sandbox command failed")
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise HomeSandboxError("sandbox command output exceeded limit")
    return result


def _live_snapshot(paths: list[Path]) -> list[dict[str, Any]]:
    return [{"index": index, "digest": _digest_file(path)} for index, path in enumerate(paths)]


def _directory_snapshot(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def visit(directory: Path) -> None:
        details = os.lstat(directory)
        if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
            _fail("synthetic state root changed")
        for entry in sorted(directory.iterdir(), key=lambda path: path.name):
            entry_details = os.lstat(entry)
            if stat.S_ISLNK(entry_details.st_mode) or _is_reparse(entry_details):
                _fail("unsafe synthetic state input")
            relative = entry.relative_to(root).as_posix()
            if stat.S_ISDIR(entry_details.st_mode):
                rows.append({"kind": "directory", "path": relative})
                visit(entry)
            elif stat.S_ISREG(entry_details.st_mode):
                rows.append({"kind": "file", "path": relative, "digest": _digest_file(entry)})
            else:
                _fail("unsafe synthetic state input")

    visit(root)
    return rows


def _snapshot_digest(snapshot: list[dict[str, str]]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()


def _version_matches(result: CommandResult, expected: str) -> bool:
    try:
        text = result.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return False
    pattern = rf"(?<![0-9A-Za-z.-]){re.escape(expected)}(?![0-9A-Za-z.-])"
    return re.search(pattern, text) is not None


def run_sandbox(spec: Mapping[str, Any], runner: CommandRunner | None = None) -> dict[str, Any]:
    _validate_spec(spec)
    command_runner = runner or SubprocessRunner()
    candidate = Path(spec["candidate_binary"])
    live_binary = Path(spec["live_binary"])
    live_paths = [live_binary, *(Path(path) for path in spec["live_config_paths"])]
    expected_candidate_digest = spec["candidate_digest"]
    if _digest_file(candidate) != expected_candidate_digest:
        _fail("candidate digest mismatch")
    live_before = _live_snapshot(live_paths)
    state_root = Path(spec["synthetic_state_root"])
    synthetic_state_before = _directory_snapshot(state_root)
    synthetic_state_digest_before = _snapshot_digest(synthetic_state_before)
    sandbox = Path(spec["sandbox_root"])
    result: dict[str, Any] | None = None
    original_error: Exception | None = None
    try:
        sandbox.mkdir(mode=0o700, parents=False, exist_ok=False)
        binary_name = "skret-candidate" + candidate.suffix
        staged_candidate = sandbox / binary_name
        staged_current = sandbox / ("skret-current" + live_binary.suffix)
        staged_backup = sandbox / ("skret-current.backup" + live_binary.suffix)
        staged_config = sandbox / "synthetic.skret.yaml"
        staged_values = sandbox / "synthetic-values.yaml"
        staged_sentinel = sandbox / ("sentinel-check" + Path(spec["sentinel_program"]).suffix)
        staged_state_root = sandbox / _STAGED_STATE_DIRECTORY
        staged_state_root.mkdir(mode=0o700)
        state_relative = _strict_relative(Path(spec["state_file"]), state_root)
        staged_state = staged_state_root / state_relative
        if not _is_within(staged_state, staged_state_root):
            _fail("staged state escaped sandbox")
        staged_manifest = staged_state_root / "state-manifest.json"
        staged_public_key = staged_state_root / "state-public-key"
        staged_journal = staged_state_root / "migration.journal.json"
        staged_source_root = sandbox / "source-state-inputs"
        staged_source_root.mkdir(mode=0o700)
        staged_source_manifest = staged_source_root / "state-manifest.json"
        staged_source_public_key = staged_source_root / "state-public-key"

        for source, destination, mode in (
            (candidate, staged_candidate, 0o700),
            (live_binary, staged_current, 0o700),
            (Path(spec["synthetic_config"]), staged_config, 0o600),
            (Path(spec["synthetic_values"]), staged_values, 0o600),
            (Path(spec["sentinel_program"]), staged_sentinel, 0o700),
            (Path(spec["state_file"]), staged_state, 0o600),
            (Path(spec["state_manifest"]), staged_source_manifest, 0o600),
            (Path(spec["state_public_key"]), staged_source_public_key, 0o600),
        ):
            _copy_regular(source, destination, mode)
        _create_staged_state_manifest(
            staged_source_manifest,
            staged_source_public_key,
            state_root,
            staged_state_root,
            staged_state,
            staged_manifest,
            staged_public_key,
        )
        if _digest_file(staged_candidate) != expected_candidate_digest:
            _fail("candidate staging mismatch")

        environment = _clean_environment(sandbox)
        version = _run_checked(command_runner, [str(staged_candidate), "--version"], environment, sandbox)
        if not _version_matches(version, spec["candidate_version"]):
            raise HomeSandboxError("candidate version mismatch")
        listed = _run_checked(
            command_runner,
            [str(staged_candidate), "list", "--config", str(staged_config), "-e", "candidate", "--format", "json"],
            environment,
            sandbox,
        )
        try:
            names = json.loads(listed.stdout.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise HomeSandboxError("invalid names-only result") from exc
        if (
            not isinstance(names, list)
            or not names
            or any(not isinstance(row, dict) or set(row) != {"key"} or not isinstance(row["key"], str) for row in names)
            or "SYNTHETIC_CANARY" not in {row["key"] for row in names}
        ):
            raise HomeSandboxError("invalid names-only result")
        _run_checked(
            command_runner,
            [str(staged_candidate), "sync", "--config", str(staged_config), "--dry-run", "--format", "json"],
            environment,
            sandbox,
        )
        _run_checked(
            command_runner,
            [str(staged_candidate), "run", "--config", str(staged_config), "-e", "candidate", "--", str(staged_sentinel)],
            environment,
            sandbox,
        )
        # The external signed manifest authorizes the copied source bytes. A
        # short-lived sandbox-only manifest binds both migrations to staged paths.
        migration = [
            str(staged_candidate),
            "sync-state",
            "migrate",
            "--state-manifest",
            str(staged_manifest),
            "--journal",
            str(staged_journal),
            "--state",
            str(staged_state),
            "--public-key",
            str(staged_public_key),
            "--role",
            "operator",
            "--audience",
            "hub",
            "--operation-id",
            "home-sandbox-local",
            "--format",
            "json",
        ]
        _run_checked(command_runner, migration, environment, sandbox)
        _run_checked(command_runner, [*migration, "--execute"], environment, sandbox)

        _copy_regular(staged_current, staged_backup, 0o700)
        staged_next = sandbox / ("skret-current.next" + live_binary.suffix)
        _copy_regular(staged_candidate, staged_next, 0o700)
        os.replace(staged_next, staged_current)
        swapped_version = _run_checked(
            command_runner,
            [str(staged_current), "--version"],
            environment,
            sandbox,
        )
        if not _version_matches(swapped_version, spec["candidate_version"]):
            raise HomeSandboxError("candidate swap smoke failed")
        os.replace(staged_backup, staged_current)
        rollback_digest = _digest_file(staged_current)
        if rollback_digest != _digest_file(live_binary):
            raise HomeSandboxError("sandbox rollback mismatch")

        live_after = _live_snapshot(live_paths)
        if live_after != live_before:
            raise HomeSandboxError("live Home state changed")
        synthetic_state_after = _directory_snapshot(state_root)
        if synthetic_state_after != synthetic_state_before:
            raise HomeSandboxError("external synthetic state changed")
        synthetic_state_digest_after = _snapshot_digest(synthetic_state_after)
        result = {
            "schema": SCHEMA,
            "status": "passed",
            "candidate_digest": expected_candidate_digest,
            "candidate_version": spec["candidate_version"],
            "rollback_digest": rollback_digest,
            "live_before": live_before,
            "live_after": live_after,
            "synthetic_state_before": synthetic_state_digest_before,
            "synthetic_state_after": synthetic_state_digest_after,
            "checks": [
                "candidate-version",
                "names-only-list",
                "sync-dry-run",
                "sentinel-child",
                "state-migration-dry-run",
                "state-migration-copied-apply",
                "atomic-swap-rollback",
            ],
        }
    except Exception as exc:
        original_error = exc
    finally:
        try:
            live_after_cleanup = _live_snapshot(live_paths)
            if live_after_cleanup != live_before:
                original_error = HomeSandboxError("live Home state changed")
        except Exception as exc:
            original_error = HomeSandboxError("live Home verification failed")
            original_error.__cause__ = exc
        try:
            if _directory_snapshot(state_root) != synthetic_state_before:
                original_error = HomeSandboxError("external synthetic state changed")
        except Exception as exc:
            original_error = HomeSandboxError("external synthetic state verification failed")
            original_error.__cause__ = exc
        try:
            if sandbox.exists() or sandbox.is_symlink():
                shutil.rmtree(sandbox)
        except OSError as exc:
            original_error = HomeSandboxError("sandbox cleanup failed")
            original_error.__cause__ = exc
    if original_error is not None:
        if isinstance(original_error, HomeSandboxError):
            raise original_error
        raise HomeSandboxError("Home sandbox failed") from original_error
    if result is None:
        raise HomeSandboxError("Home sandbox failed")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="home_sandbox.py")
    parser.add_argument("--spec", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        spec_path = _regular_path(args.spec)
        spec = parse_spec(spec_path.read_bytes())
        result = run_sandbox(spec)
        sys.stdout.write(canonical_json_bytes(result).decode("utf-8") + "\n")
        return 0
    except (HomeSandboxError, OSError, TypeError, ValueError):
        sys.stderr.write("error: Home sandbox verification failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
