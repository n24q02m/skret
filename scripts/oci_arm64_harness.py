#!/usr/bin/env python3
"""Verify exact OCI ARM64 candidates and run injected isolated scenarios."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, NamedTuple, Protocol, Sequence


SCHEMA = "skret-oci-arm64-harness/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_BLOB = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
_SECRET_ENV = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY)(?:$|_)",
    re.IGNORECASE,
)
_ALLOWED_IMAGE_ENV = frozenset({"HOME", "LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE", "TZ"})
_REQUIRED_SCENARIOS = (
    "archive-load",
    "daemon-restart",
    "names-only",
    "orphan-scavenge",
    "rollback",
    "secret-helper",
    "sentinel-child",
    "supervisor-crash",
    "sync-dry-run",
)
_SPEC_FIELDS = {
    "schema",
    "candidate_version",
    "source_sha",
    "cli_archive",
    "cli_archive_digest",
    "cli_entrypoint",
    "sync_archive",
    "sync_archive_digest",
    "sync_entrypoint",
    "launch_manifest",
    "launch_manifest_digest",
    "live_paths",
    "platform",
}
_MAX_MEMBERS = 100_000
_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
_MAX_METADATA_BYTES = 4 * 1024 * 1024


class OCIArm64HarnessError(RuntimeError):
    """A value-free OCI archive or scenario failure."""


class ScenarioResult(NamedTuple):
    name: str
    status: str
    evidence_digest: str
    persistent_matches: int


class Arm64RunRequest(NamedTuple):
    cli_archive: str
    sync_archive: str
    launch_manifest: str
    platform: str
    candidate_version: str
    source_sha: str


class Arm64Runner(Protocol):
    def run(self, request: Arm64RunRequest) -> list[ScenarioResult]: ...


def _fail(message: str = "invalid OCI ARM64 harness request") -> None:
    raise OCIArm64HarnessError(message)


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
        raise OCIArm64HarnessError("invalid OCI ARM64 JSON") from exc


def _parse_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except OCIArm64HarnessError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise OCIArm64HarnessError("invalid OCI metadata") from exc


def parse_spec(data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    raw = data.encode("utf-8", errors="strict") if isinstance(data, str) else bytes(data)
    if not raw or b"\r" in raw:
        _fail()
    parsed = _parse_json(raw)
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
        raise OCIArm64HarnessError("OCI harness input unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or _is_reparse(details) or not stat.S_ISREG(details.st_mode):
        _fail()
    return path


def _validate_entrypoint(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 64
        or any(not isinstance(part, str) or not part or len(part) > 4096 or "\x00" in part for part in value)
        or not str(value[0]).startswith("/")
    ):
        _fail()
    return tuple(value)


def _validate_spec(spec: Mapping[str, Any]) -> None:
    if set(spec) != _SPEC_FIELDS or spec.get("schema") != SCHEMA:
        _fail()
    if spec.get("platform") != "linux/arm64":
        _fail()
    if not isinstance(spec.get("candidate_version"), str) or _VERSION.fullmatch(spec["candidate_version"]) is None:
        _fail()
    if not isinstance(spec.get("source_sha"), str) or _SOURCE_SHA.fullmatch(spec["source_sha"]) is None:
        _fail()
    for name in ("cli_archive_digest", "sync_archive_digest", "launch_manifest_digest"):
        if not isinstance(spec.get(name), str) or _DIGEST.fullmatch(spec[name]) is None:
            _fail()
    _validate_entrypoint(spec.get("cli_entrypoint"))
    _validate_entrypoint(spec.get("sync_entrypoint"))
    paths = [
        _regular_path(spec.get("cli_archive")),
        _regular_path(spec.get("sync_archive")),
        _regular_path(spec.get("launch_manifest")),
    ]
    live = spec.get("live_paths")
    if not isinstance(live, list) or not live or live != sorted(set(live)):
        _fail()
    paths.extend(_regular_path(path) for path in live)
    if len(set(paths)) != len(paths):
        _fail()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            _fail("unsafe OCI harness input")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            _fail("OCI harness input changed")
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
            _fail("OCI harness input changed")
    except OCIArm64HarnessError:
        raise
    except OSError as exc:
        raise OCIArm64HarnessError("OCI harness input unavailable") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return "sha256:" + digest.hexdigest()


def _safe_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name or ":" in name:
        _fail("unsafe OCI archive")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
        _fail("unsafe OCI archive")
    return name


def _descriptor(value: Any) -> tuple[str, int]:
    if not isinstance(value, dict):
        _fail("invalid OCI descriptor")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None or type(size) is not int or size < 0:
        _fail("invalid OCI descriptor")
    return digest.removeprefix("sha256:"), size


def _read_member(archive: tarfile.TarFile, members: Mapping[str, tarfile.TarInfo], name: str, limit: int) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > limit:
        _fail("invalid OCI archive")
    stream = archive.extractfile(member)
    if stream is None:
        _fail("invalid OCI archive")
    data = stream.read(limit + 1)
    if len(data) != member.size or len(data) > limit:
        _fail("invalid OCI archive")
    return data


def _verify_blob(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    digest: str,
    size: int,
    *,
    limit: int = _MAX_TOTAL_BYTES,
) -> bytes:
    name = f"blobs/sha256/{digest}"
    member = members.get(name)
    if member is None or member.size != size or size > limit:
        _fail("invalid OCI blob")
    stream = archive.extractfile(member)
    if stream is None:
        _fail("invalid OCI blob")
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            _fail("invalid OCI blob")
        hasher.update(chunk)
        if size <= _MAX_METADATA_BYTES:
            chunks.append(chunk)
    if total != size or hasher.hexdigest() != digest:
        _fail("invalid OCI blob")
    return b"".join(chunks)


def _validate_runtime_config(
    config: Any,
    platform: Mapping[str, Any],
    expected_entrypoint: tuple[str, ...],
    version: str,
    source_sha: str,
) -> None:
    architecture = platform.get("architecture")
    operating_system = platform.get("os")
    if (
        not isinstance(config, dict)
        or config.get("architecture") != architecture
        or config.get("os") != operating_system
        or operating_system != "linux"
        or architecture not in {"amd64", "arm64"}
    ):
        _fail("invalid OCI config platform")
    runtime = config.get("config")
    if not isinstance(runtime, dict) or tuple(runtime.get("Entrypoint", ())) != expected_entrypoint:
        _fail("OCI entrypoint mismatch")
    labels = runtime.get("Labels")
    if (
        not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.version") != version
        or labels.get("org.opencontainers.image.revision") != source_sha
    ):
        _fail("OCI identity mismatch")
    environment = runtime.get("Env", [])
    if not isinstance(environment, list):
        _fail("invalid OCI environment")
    for item in environment:
        if not isinstance(item, str) or "=" not in item:
            _fail("invalid OCI environment")
        name, _, value = item.partition("=")
        if (
            name not in _ALLOWED_IMAGE_ENV
            or _SECRET_ENV.search(name)
            or "-----BEGIN" in value
            or value.lower().startswith("bearer ")
        ):
            _fail("credential-shaped OCI environment")


def _collect_platform_descriptors(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptors: Any,
    referenced: set[str],
    depth: int = 0,
) -> list[dict[str, Any]]:
    """Flatten index descriptors, descending through nested image indexes.

    Buildx OCI exports wrap per-platform manifests inside a nested index
    whose outer descriptor carries no platform; release-relevant
    descriptors always declare one explicitly.
    """
    if depth > 4:
        _fail("invalid OCI descriptor")
    if not isinstance(descriptors, list) or not descriptors:
        _fail("invalid OCI index")
    rows: list[dict[str, Any]] = []
    for row in descriptors:
        if not isinstance(row, dict):
            _fail("invalid OCI descriptor")
        if isinstance(row.get("platform"), dict):
            rows.append(row)
            continue
        digest, size = _descriptor(row)
        referenced.add(f"blobs/sha256/{digest}")
        inner = _parse_json(
            _verify_blob(archive, members, digest, size, limit=_MAX_METADATA_BYTES)
        )
        nested = inner.get("manifests") if isinstance(inner, dict) else None
        rows.extend(
            _collect_platform_descriptors(archive, members, nested, referenced, depth + 1)
        )
    return rows

def _inspect_archive(
    path: Path,
    expected_digest: str,
    expected_entrypoint: tuple[str, ...],
    version: str,
    source_sha: str,
) -> dict[str, Any]:
    if _digest_file(path) != expected_digest:
        _fail("OCI archive digest mismatch")
    selected: dict[str, Any] | None = None
    try:
        with tarfile.open(path, "r:*") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            casefolded: set[str] = set()
            total_size = 0
            for index_number, member in enumerate(archive):
                if index_number >= _MAX_MEMBERS:
                    _fail("OCI archive member limit exceeded")
                name = _safe_member_name(member.name)
                folded = name.casefold()
                if name in members or folded in casefolded:
                    _fail("OCI archive path collision")
                casefolded.add(folded)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    _fail("unsafe OCI archive member")
                if not member.isfile() and not member.isdir():
                    _fail("unsafe OCI archive member")
                if member.mode & 0o6000:
                    _fail("unsafe OCI archive mode")
                total_size += member.size
                if total_size > _MAX_TOTAL_BYTES:
                    _fail("OCI archive size limit exceeded")
                members[name] = member
            layout = _parse_json(_read_member(archive, members, "oci-layout", _MAX_METADATA_BYTES))
            if layout != {"imageLayoutVersion": "1.0.0"}:
                _fail("invalid OCI layout")
            index_document = _parse_json(_read_member(archive, members, "index.json", _MAX_METADATA_BYTES))
            descriptors = index_document.get("manifests") if isinstance(index_document, dict) else None
            if (
                not isinstance(index_document, dict)
                or index_document.get("schemaVersion") != 2
                or not isinstance(descriptors, list)
                or not descriptors
            ):
                _fail("invalid OCI index")
            referenced = {"oci-layout", "index.json"}
            platform_rows = _collect_platform_descriptors(archive, members, descriptors, referenced)
            arm64_count = 0
            for descriptor_row in platform_rows:
                if not isinstance(descriptor_row, dict) or not isinstance(descriptor_row.get("platform"), dict):
                    _fail("invalid OCI descriptor")
                platform = descriptor_row["platform"]
                manifest_digest, manifest_size = _descriptor(descriptor_row)
                manifest_name = f"blobs/sha256/{manifest_digest}"
                referenced.add(manifest_name)
                manifest = _parse_json(
                    _verify_blob(
                        archive,
                        members,
                        manifest_digest,
                        manifest_size,
                        limit=_MAX_METADATA_BYTES,
                    )
                )
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("schemaVersion") != 2
                    or not isinstance(manifest.get("layers"), list)
                ):
                    _fail("invalid OCI manifest")
                config_digest, config_size = _descriptor(manifest.get("config"))
                referenced.add(f"blobs/sha256/{config_digest}")
                config = _parse_json(
                    _verify_blob(
                        archive,
                        members,
                        config_digest,
                        config_size,
                        limit=_MAX_METADATA_BYTES,
                    )
                )
                _validate_runtime_config(config, platform, expected_entrypoint, version, source_sha)
                for layer in manifest["layers"]:
                    layer_digest, layer_size = _descriptor(layer)
                    referenced.add(f"blobs/sha256/{layer_digest}")
                    _verify_blob(archive, members, layer_digest, layer_size)
                if platform.get("architecture") == "arm64" and platform.get("os") == "linux":
                    arm64_count += 1
                    selected = {
                        "archive_digest": expected_digest,
                        "config_digest": "sha256:" + config_digest,
                        "manifest_digest": "sha256:" + manifest_digest,
                        "entrypoint": list(expected_entrypoint),
                    }
            if arm64_count != 1 or selected is None:
                _fail("missing exact linux/arm64 manifest")
            regular_files = {name for name, member in members.items() if member.isfile()}
            if regular_files != referenced:
                _fail("unbound OCI archive content")
    except OCIArm64HarnessError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise OCIArm64HarnessError("unable to inspect OCI archive") from exc
    return selected


def _live_snapshot(paths: list[Path]) -> list[dict[str, Any]]:
    return [{"index": index, "digest": _digest_file(path)} for index, path in enumerate(paths)]


def verify_inputs(spec: Mapping[str, Any]) -> dict[str, Any]:
    _validate_spec(spec)
    launch_manifest = Path(spec["launch_manifest"])
    if _digest_file(launch_manifest) != spec["launch_manifest_digest"]:
        _fail("launch manifest digest mismatch")
    cli = _inspect_archive(
        Path(spec["cli_archive"]),
        spec["cli_archive_digest"],
        _validate_entrypoint(spec["cli_entrypoint"]),
        spec["candidate_version"],
        spec["source_sha"],
    )
    sync = _inspect_archive(
        Path(spec["sync_archive"]),
        spec["sync_archive_digest"],
        _validate_entrypoint(spec["sync_entrypoint"]),
        spec["candidate_version"],
        spec["source_sha"],
    )
    return {
        "schema": SCHEMA,
        "status": "archive-verified",
        "platform": "linux/arm64",
        "candidate_version": spec["candidate_version"],
        "source_sha": spec["source_sha"],
        "launch_manifest_digest": spec["launch_manifest_digest"],
        "cli": cli,
        "sync": sync,
    }


def run_harness(spec: Mapping[str, Any], runner: Arm64Runner) -> dict[str, Any]:
    verified = verify_inputs(spec)
    live_paths = [Path(path) for path in spec["live_paths"]]
    live_before = _live_snapshot(live_paths)
    try:
        scenarios = runner.run(
            Arm64RunRequest(
                cli_archive=spec["cli_archive"],
                sync_archive=spec["sync_archive"],
                launch_manifest=spec["launch_manifest"],
                platform="linux/arm64",
                candidate_version=spec["candidate_version"],
                source_sha=spec["source_sha"],
            )
        )
    except Exception as exc:
        raise OCIArm64HarnessError("ARM64 fixture runner unavailable") from exc
    if not isinstance(scenarios, list) or len(scenarios) != len(_REQUIRED_SCENARIOS):
        _fail("incomplete ARM64 scenario matrix")
    rows: list[dict[str, Any]] = []
    for expected, scenario in zip(_REQUIRED_SCENARIOS, scenarios, strict=True):
        if (
            not isinstance(scenario, ScenarioResult)
            or scenario.name != expected
            or scenario.status != "passed"
            or not _DIGEST.fullmatch(scenario.evidence_digest)
            or type(scenario.persistent_matches) is not int
            or scenario.persistent_matches != 0
        ):
            _fail("ARM64 scenario failed")
        rows.append(
            {
                "name": scenario.name,
                "status": scenario.status,
                "evidence_digest": scenario.evidence_digest,
                "persistent_matches": scenario.persistent_matches,
            }
        )
    if (
        _digest_file(Path(spec["cli_archive"])) != spec["cli_archive_digest"]
        or _digest_file(Path(spec["sync_archive"])) != spec["sync_archive_digest"]
        or _digest_file(Path(spec["launch_manifest"])) != spec["launch_manifest_digest"]
    ):
        _fail("ARM64 fixture input changed")
    live_after = _live_snapshot(live_paths)
    if live_after != live_before:
        _fail("live OCI state changed")
    return {
        **verified,
        "status": "passed",
        "scenarios": rows,
        "live_before": live_before,
        "live_after": live_after,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oci_arm64_harness.py")
    parser.add_argument("--spec", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        spec_path = _regular_path(args.spec)
        spec = parse_spec(spec_path.read_bytes())
        sys.stdout.write(canonical_json_bytes(verify_inputs(spec)).decode("utf-8") + "\n")
        return 0
    except (OCIArm64HarnessError, OSError, TypeError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
