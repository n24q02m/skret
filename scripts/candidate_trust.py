#!/usr/bin/env python3
"""Offline Ed25519 candidate-trust result fixtures.

The result root is deliberately separate from release manifests.  This module
only creates and verifies canonical, value-free candidate evidence; it never
publishes, deploys, contacts a provider, or stores a private key.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "skret-candidate-trust/v1"
PURPOSES = frozenset(
    {
        "SK-CANDIDATE-PUBLISHED",
        "SK-CANDIDATE-EXECUTOR-READY",
        "SK-CANDIDATE-PASS",
    }
)
REQUIRED_PASS_SURFACES = frozenset({"arm64", "cloudflare", "github", "windows"})
SIGNING_DOMAIN = b"skret-candidate-trust/v1\0"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_HEX = re.compile(r"^[0-9a-f]+$")
_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "credential",
    "cookie",
    "private",
    "plaintext",
    "raw_value",
    "rawvalue",
)


class CandidateTrustError(ValueError):
    """A value-free, fail-closed candidate result error."""


def _fail(message: str = "invalid candidate result") -> None:
    raise CandidateTrustError(message)


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
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise CandidateTrustError("invalid candidate JSON") from exc


def parse_canonical_json(data: bytes | bytearray | memoryview | str) -> Any:
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="strict")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        _fail("invalid candidate JSON")
    if not raw or b"\r" in raw:
        _fail("invalid candidate JSON")
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
        if canonical_json_bytes(parsed) != raw:
            _fail("non-canonical candidate JSON")
        return parsed
    except CandidateTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CandidateTrustError("invalid candidate JSON") from exc


# RFC 8032 Ed25519, implemented with Python integers and hashlib only.  The
# private input is a 32-byte seed; no dependency with a credential store is
# introduced into the prepare lane.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _edwards_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    denominator_x = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    denominator_y = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = ((x1 * y2 + x2 * y1) * denominator_x) % _Q
    y3 = ((y1 * y2 + x1 * x2) * denominator_y) % _Q
    return x3, y3


def _scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        _fail("invalid Ed25519 key")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _Q:
        _fail("invalid Ed25519 key")
    x_squared = ((y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)) % _Q
    x = pow(x_squared, (_Q + 3) // 8, _Q)
    if (x * x - x_squared) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - x_squared) % _Q != 0:
        _fail("invalid Ed25519 key")
    if (x & 1) != sign:
        x = _Q - x
    if x == 0 and sign:
        _fail("invalid Ed25519 key")
    return x, y


def _private_seed(value: bytes | bytearray | memoryview) -> bytes:
    seed = bytes(value)
    if len(seed) != 32:
        _fail("invalid Ed25519 key")
    return seed


def public_key_from_private(private_key: bytes | bytearray | memoryview) -> bytes:
    seed = _private_seed(private_key)
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    return _encode_point(_scalar_mult(_B, scalar))


def generate_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    private = os.urandom(32) if seed is None else _private_seed(seed)
    return private, public_key_from_private(private)


def sign_bytes(message: bytes, private_key: bytes | bytearray | memoryview) -> bytes:
    seed = _private_seed(private_key)
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = _encode_point(_scalar_mult(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    encoded_r = _encode_point(_scalar_mult(_B, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % _L
    response = (nonce + challenge * scalar) % _L
    return encoded_r + response.to_bytes(32, "little")


def verify_bytes(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        encoded_r = signature[:32]
        response = int.from_bytes(signature[32:], "little")
        if response >= _L:
            return False
        point_r = _decode_point(encoded_r)
        point_a = _decode_point(public_key)
        identity = (0, 1)
        if (
            point_r == identity
            or point_a == identity
            or _scalar_mult(point_r, _L) != identity
            or _scalar_mult(point_a, _L) != identity
        ):
            return False
        challenge = int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(), "little"
        ) % _L
        left = _scalar_mult(_B, response)
        right = _edwards_add(point_r, _scalar_mult(point_a, challenge))
        return _encode_point(left) == _encode_point(right)
    except CandidateTrustError:
        return False


def _validate_digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail("invalid candidate digest")
    return value


def _validate_identity_digest(value: Any) -> str:
    if not isinstance(value, str) or (
        _DIGEST.fullmatch(value) is None and _SOURCE_SHA.fullmatch(value) is None
    ):
        _fail("invalid candidate identity")
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str) or _SOURCE_SHA.fullmatch(value) is None:
        _fail("invalid candidate source")
    return value


def _validate_id(value: Any, message: str = "invalid candidate identity") -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(message)
    return value


def _validate_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail("invalid candidate timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CandidateTrustError("invalid candidate timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        _fail("invalid candidate timestamp")
    return parsed


def _validate_safe_tree(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or any(part in key.lower() for part in _SENSITIVE_KEY_PARTS):
                _fail("sensitive candidate field")
            _validate_safe_tree(child)
    elif isinstance(value, list):
        for child in value:
            _validate_safe_tree(child)
    elif isinstance(value, str):
        # Evidence values are identifiers/digests, never arbitrary token-like
        # or private material.  Free-form strings are not accepted by any
        # canonical field validator below.
        if "-----BEGIN" in value or "bearer " in value.lower():
            _fail("sensitive candidate field")


def _validate_sorted_unique(rows: Any, key: str, message: str) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        _fail(message)
    result: list[dict[str, Any]] = []
    previous: str | None = None
    for row in rows:
        if not isinstance(row, dict) or key not in row:
            _fail(message)
        current = row[key]
        if not isinstance(current, str):
            _fail(message)
        if previous is not None and current <= previous:
            _fail("unsorted candidate fields")
        previous = current
        result.append(row)
    return result


def _validate_artifacts(rows: Any) -> list[dict[str, str]]:
    result = _validate_sorted_unique(rows, "name", "invalid candidate artifacts")
    normalized: list[dict[str, str]] = []
    for row in result:
        if set(row) != {"name", "digest", "sbom_digest", "provenance_digest"}:
            _fail("invalid candidate artifacts")
        normalized.append(
            {
                "digest": _validate_digest(row["digest"]),
                "name": _validate_id(row["name"]),
                "provenance_digest": _validate_digest(row["provenance_digest"]),
                "sbom_digest": _validate_digest(row["sbom_digest"]),
            }
        )
    return normalized


def _validate_pointers(rows: Any) -> list[dict[str, str]]:
    result = _validate_sorted_unique(rows, "surface", "invalid stable pointers")
    normalized: list[dict[str, str]] = []
    previous: tuple[str, str] | None = None
    for row in result:
        if set(row) != {"surface", "name", "digest"}:
            _fail("invalid stable pointers")
        identity = (_validate_id(row["surface"]), _validate_id(row["name"]))
        if previous is not None and identity <= previous:
            _fail("unsorted candidate fields")
        previous = identity
        normalized.append(
            {"digest": _validate_digest(row["digest"]), "name": identity[1], "surface": identity[0]}
        )
    return normalized


def _validate_surfaces(rows: Any) -> list[dict[str, str]]:
    result = _validate_sorted_unique(rows, "surface", "invalid candidate surfaces")
    normalized: list[dict[str, str]] = []
    for row in result:
        if set(row) != {"surface", "result_digest", "status"}:
            _fail("invalid candidate surfaces")
        status = row["status"]
        if status not in {"passed", "failed", "blocked", "unknown"}:
            _fail("invalid candidate surfaces")
        normalized.append(
            {
                "result_digest": _validate_digest(row["result_digest"]),
                "status": status,
                "surface": _validate_id(row["surface"]),
            }
        )
    return normalized


def _validate_teardown(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"resources", "identities", "schedules", "cost_zero"}:
        _fail("invalid candidate teardown")
    if type(value["cost_zero"]) is not bool:
        _fail("invalid candidate teardown")
    result: dict[str, Any] = {"cost_zero": value["cost_zero"]}
    for category in ("resources", "identities", "schedules"):
        rows = _validate_sorted_unique(value[category], "name", "invalid candidate teardown")
        normalized: list[dict[str, Any]] = []
        for row in rows:
            if set(row) != {"name", "remaining"}:
                _fail("invalid candidate teardown")
            if type(row["remaining"]) is not int or row["remaining"] < 0:
                _fail("invalid candidate teardown")
            normalized.append({"name": _validate_id(row["name"]), "remaining": row["remaining"]})
        result[category] = normalized
    return result


def _base_keys() -> set[str]:
    return {
        "action_sha",
        "artifacts",
        "channel",
        "expires_at",
        "generation",
        "issued_at",
        "owner",
        "previous_result_hash",
        "publisher_identity",
        "purpose",
        "schema",
        "schema_version",
        "source_sha",
        "source_manifest_digest",
        "stable_pointer_after",
        "stable_pointer_before",
        "surfaces",
        "tag",
        "teardown",
        "version",
        "workflow_sha",
    }


def _normalize_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        _fail("invalid candidate result")
    _validate_safe_tree(dict(payload))
    supplied = dict(payload)
    if "schema_version" not in supplied:
        supplied["schema_version"] = 1
    if any(key in supplied for key in ("signature", "signer_public_key", "result_hash")):
        _fail("invalid candidate result")
    required = {
        "schema",
        "purpose",
        "generation",
        "previous_result_hash",
        "source_manifest_digest",
        "source_sha",
        "workflow_sha",
        "action_sha",
        "publisher_identity",
        "artifacts",
        "stable_pointer_before",
        "stable_pointer_after",
        "surfaces",
        "teardown",
        "owner",
        "issued_at",
        "expires_at",
    }
    if not required.issubset(supplied):
        _fail("incomplete candidate result")
    allowed = _base_keys()
    if set(supplied) - allowed:
        _fail("unknown candidate field")
    if supplied["schema"] != SCHEMA or supplied["purpose"] not in PURPOSES:
        _fail("invalid candidate purpose")
    generation = supplied["generation"]
    if type(generation) is not int or generation <= 0:
        _fail("invalid candidate generation")
    previous = supplied["previous_result_hash"]
    if previous is not None:
        _validate_digest(previous)
    if generation == 1 and previous is not None:
        _fail("invalid candidate chain")
    if generation > 1 and previous is None:
        _fail("invalid candidate chain")
    if type(supplied["schema_version"]) is not int or supplied["schema_version"] != 1:
        _fail("invalid candidate schema")
    source_manifest_digest = _validate_digest(supplied["source_manifest_digest"])
    source_sha = _validate_source_sha(supplied["source_sha"])
    workflow_sha = _validate_identity_digest(supplied["workflow_sha"])
    action_sha = _validate_identity_digest(supplied["action_sha"])
    publisher = _validate_id(supplied["publisher_identity"])
    owner = _validate_id(supplied["owner"])
    issued = _validate_timestamp(supplied["issued_at"])
    expires = _validate_timestamp(supplied["expires_at"])
    if expires <= issued:
        _fail("invalid candidate validity")
    if "version" in supplied:
        _validate_id(supplied["version"])
    if "tag" in supplied:
        _validate_id(supplied["tag"])
    if "channel" in supplied and supplied["channel"] not in {"beta", "stable", "candidate"}:
        _fail("invalid candidate channel")
    artifacts = _validate_artifacts(supplied["artifacts"])
    pointers_before = _validate_pointers(supplied["stable_pointer_before"])
    pointers_after = _validate_pointers(supplied["stable_pointer_after"])
    surfaces = _validate_surfaces(supplied["surfaces"])
    teardown = _validate_teardown(supplied["teardown"])
    normalized: dict[str, Any] = {
        "action_sha": action_sha,
        "artifacts": artifacts,
        "expires_at": supplied["expires_at"],
        "generation": generation,
        "issued_at": supplied["issued_at"],
        "owner": owner,
        "previous_result_hash": previous,
        "publisher_identity": publisher,
        "purpose": supplied["purpose"],
        "schema": SCHEMA,
        "schema_version": 1,
        "source_sha": source_sha,
        "stable_pointer_after": pointers_after,
        "stable_pointer_before": pointers_before,
        "surfaces": surfaces,
        "teardown": teardown,
        "workflow_sha": workflow_sha,
        "source_manifest_digest": source_manifest_digest,
    }
    for optional in ("channel", "tag", "version"):
        if optional in supplied:
            normalized[optional] = supplied[optional]
    return normalized


def _unsigned_result(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key not in {"signature", "signer_public_key", "result_hash"}}


def _result_hash_from_base(result: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(_unsigned_result(result))).hexdigest()


def result_hash(result: Mapping[str, Any] | bytes | bytearray | memoryview | str) -> str:
    parsed = _parse_result(result)
    value = parsed.get("result_hash")
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail("invalid candidate result")
    if value != _result_hash_from_base(parsed):
        _fail("candidate result hash mismatch")
    return value


def _parse_result(result: Mapping[str, Any] | bytes | bytearray | memoryview | str) -> dict[str, Any]:
    if isinstance(result, Mapping):
        parsed = dict(result)
        # Mapping callers still must pass canonicalizable JSON; bytes callers
        # additionally prove that the original representation was canonical.
        _validate_safe_tree(parsed)
    else:
        parsed = parse_canonical_json(result)
        if not isinstance(parsed, dict):
            _fail("invalid candidate result")
    return parsed

def create_result(payload: Mapping[str, Any], private_key: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Create a signed canonical result for exactly one candidate purpose."""

    base = _normalize_payload(payload)
    digest = _result_hash_from_base(base)
    public = public_key_from_private(private_key)
    signed = dict(base)
    signed["result_hash"] = digest
    signed["signer_public_key"] = public.hex()
    signed["signature"] = sign_bytes(SIGNING_DOMAIN + canonical_json_bytes(signed), private_key).hex()
    # Validate the generated shape before returning it so callers cannot
    # accidentally persist an incomplete fixture.
    _validate_signed_shape(signed)
    return signed


def _validate_signed_shape(result: Mapping[str, Any]) -> None:
    allowed = _base_keys() | {"result_hash", "signer_public_key", "signature"}
    if set(result) - allowed or not {"result_hash", "signer_public_key", "signature"}.issubset(result):
        _fail("invalid candidate result")
    _normalize_payload({key: value for key, value in result.items() if key not in {"result_hash", "signer_public_key", "signature"}})
    digest = result.get("result_hash")
    if not isinstance(digest, str) or digest != _result_hash_from_base(result):
        _fail("candidate result hash mismatch")
    public = result.get("signer_public_key")
    signature = result.get("signature")
    if (
        not isinstance(public, str)
        or len(public) != 64
        or _HEX.fullmatch(public) is None
        or not isinstance(signature, str)
        or len(signature) != 128
        or _HEX.fullmatch(signature) is None
    ):
        _fail("invalid candidate signature")


def _parse_public_key(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, str):
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise CandidateTrustError("invalid Ed25519 key") from exc
    else:
        decoded = bytes(value)
    if len(decoded) != 32:
        _fail("invalid Ed25519 key")
    return decoded


def verify_result(
    result: Mapping[str, Any] | bytes | bytearray | memoryview | str,
    public_key: bytes | bytearray | memoryview | str,
    *,
    purpose: str | None = None,
    now: str | datetime | None = None,
    prior: Mapping[str, Any] | bytes | bytearray | memoryview | str | None = None,
    trusted_generation: int | None = None,
    trusted_result_hash: str | None = None,
) -> dict[str, Any]:
    """Verify signature, schema, validity and optional monotonic chain state."""

    parsed = _parse_result(result)
    _validate_signed_shape(parsed)
    signer = _parse_public_key(public_key)
    if parsed["signer_public_key"] != signer.hex():
        _fail("candidate signer mismatch")
    if purpose is not None and parsed["purpose"] != purpose:
        _fail("candidate purpose mismatch")
    expected_signature = parsed["signature"]
    unsigned = {key: value for key, value in parsed.items() if key not in {"signature"}}
    try:
        signature = bytes.fromhex(expected_signature)
    except ValueError as exc:
        raise CandidateTrustError("invalid candidate signature") from exc
    if not verify_bytes(SIGNING_DOMAIN + canonical_json_bytes(unsigned), signature, signer):
        _fail("candidate signature invalid")
    issued = _validate_timestamp(parsed["issued_at"])
    expires = _validate_timestamp(parsed["expires_at"])
    if now is None:
        current = datetime.now(timezone.utc)
    elif isinstance(now, datetime):
        current = now.astimezone(timezone.utc)
    else:
        current = _validate_timestamp(now)
    if current < issued or current >= expires:
        _fail("candidate result expired")
    before = parsed["stable_pointer_before"]
    after = parsed["stable_pointer_after"]
    if before != after:
        _fail("candidate stable pointer drift")
    surfaces = {row["surface"]: row for row in parsed["surfaces"]}
    required_surfaces = {
        "SK-CANDIDATE-PUBLISHED": frozenset({"github"}),
        "SK-CANDIDATE-EXECUTOR-READY": frozenset({"cloudflare"}),
        "SK-CANDIDATE-PASS": REQUIRED_PASS_SURFACES,
    }[parsed["purpose"]]
    if not required_surfaces.issubset(surfaces):
        _fail("candidate surface incomplete")
    if any(surfaces[name]["status"] != "passed" for name in required_surfaces):
        _fail("candidate surface failed")
    if parsed["purpose"] == "SK-CANDIDATE-PASS":
        teardown = parsed["teardown"]
        if teardown["cost_zero"] is not True:
            _fail("candidate teardown incomplete")
        for category in ("resources", "identities", "schedules"):
            if not teardown[category] or any(row["remaining"] != 0 for row in teardown[category]):
                _fail("candidate teardown incomplete")
    if (trusted_generation is None) != (trusted_result_hash is None):
        _fail("incomplete candidate trust head")
    current_hash = parsed["result_hash"]
    if trusted_generation is not None:
        if type(trusted_generation) is not int or trusted_generation < 0:
            _fail("invalid candidate chain")
        if parsed["generation"] <= trusted_generation:
            _fail("candidate replay or downgrade")
    if trusted_result_hash is not None:
        _validate_digest(trusted_result_hash)
        if parsed["previous_result_hash"] != trusted_result_hash:
            _fail("candidate chain mismatch")
    if prior is not None:
        prior_parsed = _parse_result(prior)
        _validate_signed_shape(prior_parsed)
        if (
            prior_parsed.get("purpose") != parsed["purpose"]
            or prior_parsed.get("signer_public_key") != signer.hex()
        ):
            _fail("candidate chain mismatch")
        prior_unsigned = {key: value for key, value in prior_parsed.items() if key != "signature"}
        try:
            prior_signature = bytes.fromhex(prior_parsed["signature"])
        except (TypeError, ValueError) as exc:
            raise CandidateTrustError("candidate chain mismatch") from exc
        if not verify_bytes(SIGNING_DOMAIN + canonical_json_bytes(prior_unsigned), prior_signature, signer):
            _fail("candidate chain mismatch")
        prior_hash = result_hash(prior_parsed)
        if parsed["generation"] <= prior_parsed["generation"]:
            _fail("candidate replay or downgrade")
        if parsed["previous_result_hash"] != prior_hash:
            _fail("candidate chain mismatch")
    del issued, expires, current, current_hash
    return parsed


# Descriptive aliases are kept in the same module so fixtures can use either
# the generic API or the contract-shaped names without importing a package.
create_candidate_result = create_result
verify_candidate_result = verify_result
create_signed_result = create_result
verify_signed_result = verify_result
sign_candidate_result = create_result
verify = verify_result
canonical_bytes = canonical_json_bytes
parse_canonical = parse_canonical_json


def _is_reparse(details: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(details, "st_file_attributes", 0) & marker)


def _read_regular_bytes(path: Path) -> bytes | None:
    try:
        path_before = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CandidateTrustError("unable to read candidate file") from exc
    if stat.S_ISLNK(path_before.st_mode) or _is_reparse(path_before) or not stat.S_ISREG(path_before.st_mode):
        _fail("unsafe candidate file")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino):
            _fail("candidate file changed")
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
            or _is_reparse(path_after)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
            or opened.st_size != after.st_size
            or getattr(opened, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
        ):
            _fail("candidate file changed")
        return b"".join(chunks)
    except CandidateTrustError:
        raise
    except OSError as exc:
        raise CandidateTrustError("unable to read candidate file") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _load_key(path: str | os.PathLike[str], *, private: bool) -> bytes:
    raw = _read_regular_bytes(Path(path))
    if raw is None:
        raise CandidateTrustError("unable to read Ed25519 key")
    if len(raw) != 32:
        try:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise CandidateTrustError("invalid Ed25519 key") from exc
    if private:
        return _private_seed(raw)
    return _parse_public_key(raw)


def _atomic_write(path: str | os.PathLike[str], data: bytes) -> None:
    destination = Path(path)
    if not destination.name or destination.name in {".", ".."}:
        _fail("unsafe candidate output")
    existing = _read_regular_bytes(destination)
    if existing is not None:
        if existing == data:
            return
        _fail("candidate output conflict")
    lock = Path(str(destination) + ".lock")
    lock_descriptor: int | None = None
    owns_lock = False
    temporary: str | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        parent = os.lstat(destination.parent)
        if stat.S_ISLNK(parent.st_mode) or _is_reparse(parent) or not stat.S_ISDIR(parent.st_mode):
            _fail("unsafe candidate output")
        lock_descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        owns_lock = True
        os.close(lock_descriptor)
        lock_descriptor = None
        existing = _read_regular_bytes(destination)
        if existing is not None:
            if existing == data:
                return
            _fail("candidate output conflict")
        fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            if _read_regular_bytes(destination) != data:
                _fail("candidate output conflict")
    except CandidateTrustError:
        raise
    except OSError as exc:
        raise CandidateTrustError("unable to write candidate output") from exc
    finally:
        if lock_descriptor is not None:
            try:
                os.close(lock_descriptor)
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="candidate_trust.py")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--input", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--private-key", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--input", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--purpose")
    verify.add_argument("--now")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "create":
            payload = parse_canonical_json(Path(args.input).read_bytes())
            signed = create_result(payload, _load_key(args.private_key, private=True))
            _atomic_write(args.output, canonical_json_bytes(signed))
            sys.stdout.write(canonical_json_bytes({"result_hash": result_hash(signed)}).decode() + "\n")
        else:
            result = parse_canonical_json(Path(args.input).read_bytes())
            verified = verify_result(
                result,
                _load_key(args.public_key, private=False),
                purpose=args.purpose,
                now=args.now,
            )
            sys.stdout.write(canonical_json_bytes({"ok": True, "result_hash": result_hash(verified)}).decode() + "\n")
        return 0
    except (CandidateTrustError, OSError, TypeError, ValueError):
        sys.stderr.write("error: candidate trust verification failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
