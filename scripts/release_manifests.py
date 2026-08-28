#!/usr/bin/env python3
"""Deterministic, source-only release manifests.

This module intentionally has no network or publication capabilities.  It
walks a caller-provided tree, refuses symlinks and unsafe relative paths, and
writes canonical JSON plus a separate digest without overwriting a conflicting
existing file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
SCHEMA = "skret-release-manifest/v1"
MERKLE_LEAF_DOMAIN = b"skret-release-manifest-leaf/v1\0"
MERKLE_NODE_DOMAIN = b"skret-release-manifest-node/v1\0"
MERKLE_EMPTY_DOMAIN = b"skret-release-manifest-empty/v1\0"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,255}$")


class ManifestError(ValueError):
    """A value-free manifest validation or persistence error."""


class ManifestConflict(ManifestError):
    """An existing output does not contain the exact requested bytes."""


def _fail(message: str = "invalid manifest") -> None:
    # Keep every public error deliberately value-free.  Callers must not get
    # path contents, environment values, or arbitrary JSON echoed to logs.
    raise ManifestError(message)


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a value using the single JSON representation used for signing."""

    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return text.encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise ManifestError("invalid manifest JSON") from exc


def parse_canonical_json(data: bytes | bytearray | memoryview | str) -> Any:
    """Parse JSON and reject duplicate keys, non-finite values, or reformatting."""

    if isinstance(data, str):
        raw = data.encode("utf-8", errors="strict")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        _fail("invalid manifest JSON")
    if not raw or b"\r" in raw:
        _fail("invalid manifest JSON")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
        if canonical_json_bytes(value) != raw:
            _fail("non-canonical manifest JSON")
        return value
    except ManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ManifestError("invalid manifest JSON") from exc


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail("unsafe manifest path")
    if "\\" in value:
        _fail("unsafe manifest path")
    path = PurePosixPath(value)
    if path.is_absolute() or ":" in value:
        _fail("unsafe manifest path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail("unsafe manifest path")
    normalized = "/".join(parts)
    if normalized != value:
        _fail("unsafe manifest path")
    return normalized


def _validate_excludes(excludes: Iterable[str] | None) -> tuple[str, ...]:
    values = {_validate_relative_path(item) for item in (excludes or ())}
    return tuple(sorted(values))


def _is_excluded(relative: str, excludes: Sequence[str]) -> bool:
    return any(relative == item or relative.startswith(item + "/") for item in excludes)


def _is_reparse_stat(details: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return bool(reparse and attributes & reparse)


def _root_path(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError, OSError) as exc:
        raise ManifestError("invalid manifest root") from exc
    try:
        details = os.lstat(path)
        if (
            stat.S_ISLNK(details.st_mode)
            or _is_reparse_stat(details)
            or not stat.S_ISDIR(details.st_mode)
        ):
            _fail("invalid manifest root")
        # The caller selects the root. Every descendant is checked without
        # following links or Windows reparse points.
        return path.absolute()
    except OSError as exc:
        raise ManifestError("invalid manifest root") from exc


def _hash_regular_file(path: str) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        path_before = os.lstat(path)
        if (
            stat.S_ISLNK(path_before.st_mode)
            or _is_reparse_stat(path_before)
            or not stat.S_ISREG(path_before.st_mode)
        ):
            _fail("unsafe manifest entry")
        descriptor = os.open(path, flags | nofollow)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError("unable to read manifest file") from exc
    digest = hashlib.sha256()
    length = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("unsafe manifest entry")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            length += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            stat.S_ISLNK(path_after.st_mode)
            or _is_reparse_stat(path_after)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino)
            or (path_before.st_dev, path_before.st_ino) != (path_after.st_dev, path_after.st_ino)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (before.st_dev, before.st_ino) != (path_after.st_dev, path_after.st_ino)
            or before.st_size != after.st_size
            or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
            or getattr(before, "st_ctime_ns", None) != getattr(after, "st_ctime_ns", None)
        ):
            _fail("manifest file changed")
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError("unable to read manifest file") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return length, digest.hexdigest()


def inventory(root: str | os.PathLike[str], excludes: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Return sorted regular-file rows without following symlinks."""

    root_path = _root_path(root)
    excluded = _validate_excludes(excludes)
    rows: list[dict[str, Any]] = []

    def visit(directory: Path, prefix: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise ManifestError("unable to read manifest root") from exc
        for entry in entries:
            name = entry.name
            if not name or name in (".", "..") or "\x00" in name or "\\" in name:
                _fail("unsafe manifest path")
            relative = f"{prefix}/{name}" if prefix else name
            _validate_relative_path(relative)
            # A declared exclusion never grants permission to traverse a
            # symlink.  Reject it before evaluating the exclusion.
            try:
                details = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or stat.S_ISLNK(details.st_mode) or _is_reparse_stat(details):
                    _fail("symlink in manifest root")
                is_directory = stat.S_ISDIR(details.st_mode)
                is_file = stat.S_ISREG(details.st_mode)
            except ManifestError:
                raise
            except OSError as exc:
                raise ManifestError("unsafe manifest entry") from exc
            if _is_excluded(relative, excluded):
                continue
            if is_directory:
                visit(Path(entry.path), relative)
            elif is_file:
                length, digest = _hash_regular_file(entry.path)
                rows.append({"path": relative, "length": length, "sha256": digest})
            else:
                _fail("unsafe manifest entry")

    visit(root_path, "")
    rows.sort(key=lambda row: row["path"])
    return rows


def _validate_digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail("invalid manifest digest")
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str) or _SOURCE_SHA.fullmatch(value) is None:
        _fail("invalid source SHA")
    return value


def _validate_identifier(value: Any, message: str = "invalid manifest identifier") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail(message)
    return value


def _validate_rows(rows: Any, *, require_sorted: bool = True) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        _fail("invalid manifest inventory")
    result: list[dict[str, Any]] = []
    previous: str | None = None
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "length", "sha256"}:
            _fail("invalid manifest inventory")
        path = _validate_relative_path(row["path"])
        length = row["length"]
        if type(length) is not int or length < 0:
            _fail("invalid manifest inventory")
        digest = row["sha256"]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _fail("invalid manifest inventory")
        if require_sorted and previous is not None and path <= previous:
            _fail("unsorted manifest inventory")
        previous = path
        result.append({"path": path, "length": length, "sha256": digest})
    return result


def merkle_root(rows: Sequence[Mapping[str, Any]]) -> str:
    """Compute the domain-separated root while preserving row order."""

    normalized = _validate_rows(list(rows), require_sorted=False)
    if not normalized:
        return "sha256:" + hashlib.sha256(MERKLE_EMPTY_DOMAIN).hexdigest()
    level = [
        hashlib.sha256(MERKLE_LEAF_DOMAIN + canonical_json_bytes(row)).digest()
        for row in normalized
    ]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            if index + 1 == len(level):
                next_level.append(left)
            else:
                next_level.append(hashlib.sha256(MERKLE_NODE_DOMAIN + left + level[index + 1]).digest())
        level = next_level
    return "sha256:" + level[0].hex()


def _relative_if_inside(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> str | None:
    try:
        root_path = _root_path(root)
        candidate_path = Path(candidate).absolute()
        relative = os.path.relpath(candidate_path, root_path)
    except (OSError, ValueError, ManifestError):
        return None
    if relative == os.curdir or relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return None
    return _validate_relative_path(relative.replace(os.sep, "/"))


def build_manifest(
    kind: str,
    root: str | os.PathLike[str],
    *,
    source_sha: str,
    version: str,
    tag: str,
    channel: str,
    source_manifest_digest: str | None = None,
    artifact_manifest_digest: str | None = None,
    excludes: Iterable[str] | None = None,
    manifest_path: str | None = None,
    signature_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a canonical manifest object for a clean source/artifact root."""

    if kind not in {"source", "artifact", "deployment"}:
        _fail("invalid manifest kind")
    if kind == "source" and (source_manifest_digest is not None or artifact_manifest_digest is not None):
        _fail("invalid source manifest binding")
    if kind == "artifact" and artifact_manifest_digest is not None:
        _fail("invalid artifact manifest binding")
    if kind in {"artifact", "deployment"} and source_manifest_digest is None:
        _fail("missing source manifest digest")
    _validate_source_sha(source_sha)
    _validate_identifier(version)
    _validate_identifier(tag)
    if channel not in {"beta", "stable", "candidate"}:
        _fail("invalid manifest channel")
    if source_manifest_digest is not None:
        _validate_digest(source_manifest_digest)
    if artifact_manifest_digest is not None:
        _validate_digest(artifact_manifest_digest)
    all_excludes = list(excludes or ())
    if manifest_path is not None:
        all_excludes.append(manifest_path)
    all_excludes.extend(signature_paths or ())
    rows = inventory(root, all_excludes)
    result: dict[str, Any] = {
        "channel": channel,
        "files": rows,
        "file_count": len(rows),
        "kind": kind,
        "merkle_root": merkle_root(rows),
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source_sha": source_sha,
        "tag": tag,
        "version": version,
        "byte_count": sum(row["length"] for row in rows),
    }
    if source_manifest_digest is not None:
        result["source_manifest_digest"] = source_manifest_digest
    if artifact_manifest_digest is not None:
        result["artifact_manifest_digest"] = artifact_manifest_digest
    return result
def _validate_manifest_object(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        _fail("invalid manifest object")
    value = dict(manifest)
    base = {
        "schema",
        "schema_version",
        "kind",
        "source_sha",
        "version",
        "tag",
        "channel",
        "files",
        "file_count",
        "byte_count",
        "merkle_root",
    }
    kind = value.get("kind")
    allowed = set(base)
    if kind in {"artifact", "deployment"}:
        allowed.add("source_manifest_digest")
    if kind == "deployment" and "artifact_manifest_digest" in value:
        allowed.add("artifact_manifest_digest")
    if (
        set(value) != allowed
        or value.get("schema") != SCHEMA
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
        or kind not in {"source", "artifact", "deployment"}
    ):
        _fail("invalid manifest object")
    _validate_source_sha(value.get("source_sha"))
    _validate_identifier(value.get("version"))
    _validate_identifier(value.get("tag"))
    if value.get("channel") not in {"beta", "stable", "candidate"}:
        _fail("invalid manifest channel")
    rows = _validate_rows(value.get("files"))
    if (
        type(value.get("file_count")) is not int
        or value["file_count"] != len(rows)
        or type(value.get("byte_count")) is not int
        or value["byte_count"] != sum(row["length"] for row in rows)
        or value.get("merkle_root") != merkle_root(rows)
    ):
        _fail("invalid manifest inventory")
    if kind in {"artifact", "deployment"}:
        _validate_digest(value.get("source_manifest_digest"))
    if "artifact_manifest_digest" in value:
        _validate_digest(value["artifact_manifest_digest"])
    return value




def _output_path(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError, OSError) as exc:
        raise ManifestError("invalid manifest output") from exc
    if not str(path) or path.name in ("", ".", ".."):
        _fail("invalid manifest output")
    if path.exists() and path.is_symlink():
        _fail("unsafe manifest output")
    return path


def _existing_bytes(path: Path) -> bytes | None:
    try:
        path_before = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ManifestError("unable to read manifest output") from exc
    if (
        stat.S_ISLNK(path_before.st_mode)
        or _is_reparse_stat(path_before)
        or not stat.S_ISREG(path_before.st_mode)
    ):
        _fail("unsafe manifest output")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            _fail("unsafe manifest output")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            stat.S_ISLNK(path_after.st_mode)
            or _is_reparse_stat(path_after)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
            or opened.st_size != after.st_size
            or getattr(opened, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
        ):
            _fail("manifest output changed")
        return b"".join(chunks)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError("unable to read manifest output") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _atomic_write(path: Path, data: bytes) -> None:
    path = _output_path(path)
    existing = _existing_bytes(path)
    if existing is not None:
        if existing == data:
            return
        raise ManifestConflict("manifest output conflict")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        parent = os.lstat(path.parent)
        if stat.S_ISLNK(parent.st_mode) or _is_reparse_stat(parent) or not stat.S_ISDIR(parent.st_mode):
            _fail("unsafe manifest output")
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError("unable to create manifest output") from exc
    lock = Path(str(path) + ".lock")
    descriptor: int | None = None
    temporary: str | None = None
    owns_lock = False
    try:
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            owns_lock = True
        except OSError as exc:
            raise ManifestConflict("manifest output conflict") from exc
        os.close(descriptor)
        descriptor = None
        existing = _existing_bytes(path)
        if existing is not None:
            if existing == data:
                return
            raise ManifestConflict("manifest output conflict")
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _existing_bytes(path) != data:
                raise ManifestConflict("manifest output conflict")
    except ManifestConflict:
        raise
    except OSError as exc:
        raise ManifestError("unable to write manifest output") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        if owns_lock:
            try:
                os.unlink(lock)
            except OSError:
                pass


def write_manifest(
    manifest: Mapping[str, Any],
    output: str | os.PathLike[str],
    digest_output: str | os.PathLike[str] | None = None,
) -> str:
    """Atomically write a manifest and optional plain-hex digest sidecar."""

    encoded = canonical_json_bytes(_validate_manifest_object(manifest))
    digest = hashlib.sha256(encoded).hexdigest()
    output_path = _output_path(output)
    digest_path = _output_path(digest_output) if digest_output is not None else None
    if digest_path is not None and digest_path == output_path:
        _fail("invalid manifest output")
    digest_bytes = (digest + "\n").encode("ascii")
    # Preflight both destinations so a sidecar conflict cannot cause a new
    # manifest to be installed before the operation fails.
    if _existing_bytes(output_path) not in (None, encoded):
        raise ManifestConflict("manifest output conflict")
    if digest_path is not None and _existing_bytes(digest_path) not in (None, digest_bytes):
        raise ManifestConflict("manifest output conflict")
    _atomic_write(output_path, encoded)
    if digest_path is not None:
        _atomic_write(digest_path, digest_bytes)
    return "sha256:" + digest

def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(_validate_manifest_object(manifest))
    ).hexdigest()



def read_manifest(path: str | os.PathLike[str]) -> dict[str, Any]:
    output = _output_path(path)
    encoded = _existing_bytes(output)
    if encoded is None:
        raise ManifestError("unable to read manifest output")
    value = parse_canonical_json(encoded)
    if not isinstance(value, dict):
        _fail("invalid manifest object")
    return _validate_manifest_object(value)


def verify_manifest(
    manifest_path: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    excludes: Iterable[str] | None = None,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Re-inventory a root and fail closed when any bound byte changes."""

    manifest = read_manifest(manifest_path)
    kind = manifest.get("kind")
    if kind not in {"source", "artifact", "deployment"}:
        _fail("invalid manifest object")
    required = {key: manifest.get(key) for key in ("source_sha", "version", "tag", "channel")}
    source_digest = manifest.get("source_manifest_digest")
    artifact_digest = manifest.get("artifact_manifest_digest")
    auto_excludes = list(excludes or ())
    relative_manifest = _relative_if_inside(root, manifest_path)
    if relative_manifest is not None:
        auto_excludes.append(relative_manifest)
        if relative_manifest.endswith(".json"):
            auto_excludes.append(relative_manifest[:-5] + ".sha256")
    rebuilt = build_manifest(
        kind,
        root,
        source_sha=required["source_sha"],
        version=required["version"],
        tag=required["tag"],
        channel=required["channel"],
        source_manifest_digest=source_digest,
        artifact_manifest_digest=artifact_digest,
        excludes=auto_excludes,
    )
    if expected is not None:
        for key, value in expected.items():
            if manifest.get(key) != value:
                _fail("manifest binding mismatch")
    if rebuilt != manifest:
        _fail("manifest content mismatch")
    return manifest
canonical_bytes = canonical_json_bytes
parse_canonical = parse_canonical_json
generate_manifest = build_manifest
write = write_manifest



def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release_manifests.py")
    subparsers = parser.add_subparsers(dest="kind", required=True)
    for kind in ("source", "artifact", "deployment"):
        command = subparsers.add_parser(kind)
        command.add_argument("--root", required=True)
        command.add_argument("--output", required=True)
        command.add_argument("--digest-output", required=False)
        command.add_argument("--source-sha", required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--tag", required=True)
        command.add_argument("--channel", required=True)
        command.add_argument("--source-manifest-digest", required=kind != "source")
        command.add_argument("--artifact-manifest-digest", required=False)
        command.add_argument("--exclude", action="append", default=[])
        command.add_argument("--manifest-path", action="append", default=[])
        command.add_argument("--signature-path", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        excludes = list(args.exclude) + list(args.manifest_path) + list(args.signature_path)
        for candidate in (args.output, args.digest_output):
            if candidate:
                relative = _relative_if_inside(args.root, candidate)
                if relative is not None:
                    excludes.append(relative)
        manifest = build_manifest(
            args.kind,
            args.root,
            source_sha=args.source_sha,
            version=args.version,
            tag=args.tag,
            channel=args.channel,
            source_manifest_digest=args.source_manifest_digest,
            artifact_manifest_digest=args.artifact_manifest_digest,
            excludes=excludes,
        )
        digest = write_manifest(manifest, args.output, args.digest_output)
        sys.stdout.write(canonical_json_bytes({"digest": digest}).decode("utf-8") + "\n")
        return 0
    except ManifestError:
        sys.stderr.write("error: manifest generation failed\n")
        return 1
    except (OSError, ValueError, TypeError):
        sys.stderr.write("error: manifest generation failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
