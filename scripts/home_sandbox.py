#!/usr/bin/env python3
"""Run exact Skret candidates in an isolated Home-compatible sandbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, NamedTuple, Protocol, Sequence

SCHEMA = "skret-home-sandbox/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
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


def _regular_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail()
    path = Path(value)
    if not path.is_absolute():
        _fail()
    try:
        details = os.lstat(path)
    except OSError as exc:
        raise HomeSandboxError("sandbox input unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISREG(details.st_mode):
        _fail()
    return path

def _regular_directory(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail()
    path = Path(value)
    if not path.is_absolute():
        _fail()
    try:
        details = os.lstat(path)
    except OSError as exc:
        raise HomeSandboxError("sandbox input unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
        _fail()
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_synthetic_state_root(
    state_root: Path,
    state_file: Path,
    state_manifest: Path,
    state_public_key: Path,
) -> None:
    if any(not _is_within(path, state_root) for path in (state_file, state_manifest, state_public_key)):
        _fail()
    try:
        document = json.loads(
            state_manifest.read_text(encoding="utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HomeSandboxError("invalid synthetic state manifest") from exc
    if not isinstance(document, dict):
        _fail()
    source_root = document.get("source_root")
    files = document.get("files")
    if not isinstance(source_root, str) or Path(source_root) != state_root or not isinstance(files, list):
        _fail()
    state_relative = state_file.relative_to(state_root).as_posix()
    matches = sum(
        isinstance(row, dict) and row.get("path") == state_relative
        for row in files
    )
    if matches != 1:
        _fail()


def _new_sandbox_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail()
    path = Path(value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
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
    state_root = _regular_directory(spec.get("synthetic_state_root"))
    state_file = _regular_path(spec.get("state_file"))
    state_manifest = _regular_path(spec.get("state_manifest"))
    state_public_key = _regular_path(spec.get("state_public_key"))
    _validate_synthetic_state_root(state_root, state_file, state_manifest, state_public_key)
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
    sandbox = _new_sandbox_path(spec.get("sandbox_root"))
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
        staged_state = sandbox / "state.v1.json"
        staged_manifest = sandbox / "state-manifest.json"
        staged_public_key = sandbox / "state-public-key"
        staged_journal = sandbox / "migration.journal.json"

        for source, destination, mode in (
            (candidate, staged_candidate, 0o700),
            (live_binary, staged_current, 0o700),
            (Path(spec["synthetic_config"]), staged_config, 0o600),
            (Path(spec["synthetic_values"]), staged_values, 0o600),
            (Path(spec["sentinel_program"]), staged_sentinel, 0o700),
            (Path(spec["state_file"]), staged_state, 0o600),
            (Path(spec["state_manifest"]), staged_manifest, 0o600),
            (Path(spec["state_public_key"]), staged_public_key, 0o600),
        ):
            _copy_regular(source, destination, mode)
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
        result = {
            "schema": SCHEMA,
            "status": "passed",
            "candidate_digest": expected_candidate_digest,
            "candidate_version": spec["candidate_version"],
            "rollback_digest": rollback_digest,
            "live_before": live_before,
            "live_after": live_after,
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
