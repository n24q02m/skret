#!/usr/bin/env python3
"""Durable, append-only release transaction journal.

The journal is intentionally small and offline. It records one transaction per
JSONL file and does not publish, deploy, or otherwise perform a remote write.
Every line is canonical JSON and carries a hash of its unsigned contents plus
the hash of the preceding line. A malformed, partial, reordered, or otherwise
ambiguous journal is rejected; this module never repairs or truncates it.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


SCHEMA_VERSION = 1
MAX_IDENTIFIER_LENGTH = 128
MAX_TIMESTAMP_LENGTH = 40
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RFC3339 = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?P<fraction>\.[0-9]+)?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})$"
)

_STATES = frozenset(
    {
        "prepared",
        "approved",
        "dispatching",
        "dispatched",
        "completed",
        "needs_reconciliation",
    }
)
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "prepared": frozenset({"approved"}),
    "approved": frozenset({"dispatching"}),
    "dispatching": frozenset({"dispatched", "needs_reconciliation"}),
    "dispatched": frozenset({"completed", "needs_reconciliation"}),
    "needs_reconciliation": frozenset({"dispatched", "completed"}),
    "completed": frozenset(),
}

_INIT_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "previous_hash",
        "record_hash",
        "event_id",
        "event_type",
        "transaction_id",
        "channel",
        "source_sha",
        "artifact_digest",
        "intent_digest",
        "state",
        "timestamp",
    }
)
_TRANSITION_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "previous_hash",
        "record_hash",
        "event_id",
        "event_type",
        "transaction_id",
        "from_state",
        "state",
        "timestamp",
    }
)
_TRANSITION_OPTIONAL_KEYS = frozenset({"external_id", "observation_digest"})


class JournalError(RuntimeError):
    """A value-free, fail-closed journal error."""


class ConflictError(JournalError):
    """An already-used identity or event does not match the requested bytes."""


class FaultInjected(JournalError):
    """A test-only write fault was requested."""


# Tests may install a one-shot or persistent callback. The environment hook is
# useful for subprocess tests and has no effect unless explicitly requested.
fault_injector: Callable[[str], None] | None = None


def set_fault_injector(injector: Callable[[str], None] | None) -> None:
    """Install a write fault callback, or clear the current callback."""

    global fault_injector
    fault_injector = injector


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise JournalError("non-canonical journal value") from exc
    return encoded.encode("utf-8")


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _parse_canonical_line(line: bytes) -> dict[str, Any]:
    if not line or b"\r" in line:
        raise JournalError("invalid journal line")
    try:
        text = line.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise JournalError("invalid journal line") from exc
    if not isinstance(parsed, dict):
        raise JournalError("invalid journal row")
    canonical = _canonical_bytes(parsed)
    if canonical != line:
        raise JournalError("non-canonical journal line")
    return parsed


def _validate_identifier(value: Any, field: str) -> str:
    del field  # Kept in the signature so callers identify the checked field.
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_IDENTIFIER_LENGTH):
        raise JournalError("invalid journal identifier")
    if _IDENTIFIER.fullmatch(value) is None:
        raise JournalError("invalid journal identifier")
    if any(ord(char) > 0x7F or ord(char) < 0x21 for char in value):
        raise JournalError("invalid journal identifier")
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str) or _HEX40.fullmatch(value) is None:
        raise JournalError("invalid source digest")
    return value


def _validate_digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise JournalError("invalid digest")
    return value


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_TIMESTAMP_LENGTH):
        raise JournalError("invalid timestamp")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise JournalError("invalid timestamp")
    try:
        year, month, day = (int(part) for part in match.group("date").split("-"))
        hour, minute, second = (int(part) for part in match.group("clock").split(":"))
        fraction = match.group("fraction")
        microsecond = 0
        if fraction:
            digits = fraction[1:]
            microsecond = int((digits + "000000")[:6])
        zone = match.group("zone")
        if zone == "Z":
            offset = _datetime.timezone.utc
        else:
            offset_hours = int(zone[1:3])
            offset_minutes = int(zone[4:6])
            if offset_hours > 23 or offset_minutes > 59:
                raise ValueError("invalid timezone")
            sign = 1 if zone[0] == "+" else -1
            offset = _datetime.timezone(
                _datetime.timedelta(
                    minutes=sign * (offset_hours * 60 + offset_minutes)
                )
            )
        _datetime.datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tzinfo=offset,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise JournalError("invalid timestamp") from exc
    return value


def _require_int(value: Any) -> int:
    if type(value) is not int:
        raise JournalError("invalid journal number")
    return value


def _compute_hash(row: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in row.items() if key != "record_hash"}
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def _event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return the caller-controlled portion used for idempotency comparison."""

    return {
        key: value
        for key, value in row.items()
        if key not in {"sequence", "previous_hash", "record_hash"}
    }


def _validate_row_shape(row: Mapping[str, Any]) -> None:
    if type(row.get("schema_version")) is not int or row["schema_version"] != SCHEMA_VERSION:
        raise JournalError("unsupported journal schema")
    sequence = _require_int(row.get("sequence"))
    if sequence < 0:
        raise JournalError("invalid journal sequence")
    previous_hash = row.get("previous_hash")
    if previous_hash is not None and (
        not isinstance(previous_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", previous_hash) is None
    ):
        raise JournalError("invalid previous journal hash")
    record_hash = row.get("record_hash")
    if not isinstance(record_hash, str) or re.fullmatch(r"[0-9a-f]{64}", record_hash) is None:
        raise JournalError("invalid journal hash")
    event_type = row.get("event_type")
    if event_type not in {"init", "transition"}:
        raise JournalError("invalid journal event")

    if event_type == "init":
        if set(row) != _INIT_KEYS:
            raise JournalError("invalid init row")
        if sequence != 0 or previous_hash is not None:
            raise JournalError("invalid init position")
        _validate_identifier(row.get("event_id"), "event_id")
        if row.get("event_id") != "init":
            raise JournalError("invalid init event")
        _validate_identifier(row.get("transaction_id"), "transaction_id")
        if row.get("channel") not in {"beta", "stable"}:
            raise JournalError("invalid release channel")
        _validate_source_sha(row.get("source_sha"))
        _validate_digest(row.get("artifact_digest"))
        _validate_digest(row.get("intent_digest"))
        if row.get("state") != "prepared":
            raise JournalError("invalid init state")
        _validate_timestamp(row.get("timestamp"))
    else:
        if not _TRANSITION_REQUIRED_KEYS.issubset(row):
            raise JournalError("invalid transition row")
        allowed_keys = _TRANSITION_REQUIRED_KEYS | _TRANSITION_OPTIONAL_KEYS
        if not set(row).issubset(allowed_keys):
            raise JournalError("invalid transition row")
        if previous_hash is None:
            raise JournalError("invalid transition position")
        _validate_identifier(row.get("transaction_id"), "transaction_id")
        _validate_identifier(row.get("event_id"), "event_id")
        from_state = row.get("from_state")
        state = row.get("state")
        if from_state not in _STATES or state not in _STATES:
            raise JournalError("invalid transition state")
        _validate_timestamp(row.get("timestamp"))
        if "external_id" in row:
            _validate_identifier(row.get("external_id"), "external_id")
        if "observation_digest" in row:
            _validate_digest(row.get("observation_digest"))


def _validate_chain(rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        raise JournalError("empty journal")
    first = rows[0]
    if first.get("event_type") != "init":
        raise JournalError("journal must start with init")
    identity = (
        first.get("transaction_id"),
        first.get("channel"),
        first.get("source_sha"),
        first.get("artifact_digest"),
        first.get("intent_digest"),
    )
    current_state = "prepared"
    seen_events: set[str] = {"init"}
    prior_hash: str | None = None

    for expected_sequence, row in enumerate(rows):
        if not isinstance(row, dict):
            raise JournalError("invalid journal row")
        _validate_row_shape(row)
        if row["sequence"] != expected_sequence:
            raise JournalError("invalid journal sequence")
        if row["previous_hash"] != prior_hash:
            raise JournalError("broken journal chain")
        if _compute_hash(row) != row["record_hash"]:
            raise JournalError("invalid journal hash")
        if row["event_type"] == "init":
            if expected_sequence != 0:
                raise JournalError("multiple init rows")
        else:
            if row["transaction_id"] != identity[0]:
                raise JournalError("transaction identity conflict")
            event_id = row["event_id"]
            if event_id in seen_events:
                raise JournalError("duplicate journal event")
            seen_events.add(event_id)
            from_state = row["from_state"]
            state = row["state"]
            _check_transition(
                current_state,
                from_state,
                state,
                row.get("external_id"),
                row.get("observation_digest"),
            )
            current_state = state
        prior_hash = row["record_hash"]


def _check_transition(
    current_state: str,
    from_state: Any,
    state: Any,
    external_id: Any,
    observation_digest: Any,
) -> None:
    if from_state != current_state or state not in _ALLOWED_TRANSITIONS[current_state]:
        raise JournalError("invalid transition")
    if state == "dispatched" and external_id is None:
        raise JournalError("dispatch evidence required")
    requires_observation = state == "needs_reconciliation" or current_state == "needs_reconciliation"
    if requires_observation and observation_digest is None:
        raise JournalError("reconciliation evidence required")


def _journal_path(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError) as exc:
        raise JournalError("invalid journal path") from exc
    if not str(path):
        raise JournalError("invalid journal path")
    return path


@contextmanager
def _exclusive_lock(journal: Path) -> Iterator[None]:
    """Acquire an inter-process lock on a stable sidecar path."""

    lock_path = Path(f"{journal}.lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+b")
    except (OSError, ValueError) as exc:
        raise JournalError("unable to lock journal") from exc
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            locked = True
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            locked = True
        yield
    except (OSError, ValueError) as exc:
        raise JournalError("unable to lock journal") from exc
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            handle.close()
        except OSError:
            pass


def _load_rows(journal: Path) -> list[dict[str, Any]]:
    try:
        data = journal.read_bytes()
    except FileNotFoundError as exc:
        raise JournalError("journal is missing") from exc
    except OSError as exc:
        raise JournalError("journal cannot be read") from exc
    if not data or not data.endswith(b"\n"):
        raise JournalError("journal has an incomplete tail")
    lines = data.split(b"\n")
    if lines[-1] != b"":
        raise JournalError("journal has an incomplete tail")
    rows = [_parse_canonical_line(line) for line in lines[:-1]]
    _validate_chain(rows)
    return rows


def _fault(point: str) -> None:
    callback = fault_injector
    if callback is not None:
        callback(point)
    if os.environ.get("RELEASE_TRANSACTION_FAULT") == point:
        raise FaultInjected("fault injected")


def _write_all(stream: Any, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = stream.write(data[offset:])
        if not isinstance(written, int) or written <= 0:
            raise JournalError("journal append failed")
        offset += written


def _append_row(journal: Path, row: Mapping[str, Any]) -> None:
    encoded = _canonical_bytes(row) + b"\n"
    journal.parent.mkdir(parents=True, exist_ok=True)
    _fault("before_append")
    try:
        stream = open(journal, "ab", buffering=0)
    except OSError as exc:
        raise JournalError("journal append failed") from exc
    try:
        if os.environ.get("RELEASE_TRANSACTION_FAULT") == "partial":
            partial = encoded[: max(1, len(encoded) // 2)]
            _write_all(stream, partial)
            stream.flush()
            raise FaultInjected("fault injected")
        _write_all(stream, encoded)
        stream.flush()
        _fault("after_flush")
        _fault("before_fsync")
        try:
            os.fsync(stream.fileno())
        except OSError as exc:
            raise JournalError("journal append failed") from exc
    except (OSError, ValueError):
        raise JournalError("journal append failed")
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _status_object(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    first = rows[0]
    latest = rows[-1]
    result: dict[str, Any] = {
        "channel": first["channel"],
        "record_hash": latest["record_hash"],
        "schema_version": SCHEMA_VERSION,
        "sequence": latest["sequence"],
        "state": latest["state"],
        "transaction_id": first["transaction_id"],
    }
    for evidence_key in ("external_id", "observation_digest"):
        for row in reversed(rows):
            if evidence_key in row:
                result[evidence_key] = row[evidence_key]
                break
    return result


def initialize(
    journal: str | os.PathLike[str],
    transaction_id: str,
    channel: str,
    source_sha: str,
    artifact_digest: str,
    intent_digest: str,
    timestamp: str,
) -> dict[str, Any]:
    """Create a journal or idempotently re-submit its exact init event."""

    journal_path = _journal_path(journal)
    _validate_identifier(transaction_id, "transaction_id")
    if channel not in {"beta", "stable"}:
        raise JournalError("invalid release channel")
    _validate_source_sha(source_sha)
    _validate_digest(artifact_digest)
    _validate_digest(intent_digest)
    _validate_timestamp(timestamp)
    candidate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sequence": 0,
        "previous_hash": None,
        "record_hash": "",
        "event_id": "init",
        "event_type": "init",
        "transaction_id": transaction_id,
        "channel": channel,
        "source_sha": source_sha,
        "artifact_digest": artifact_digest,
        "intent_digest": intent_digest,
        "state": "prepared",
        "timestamp": timestamp,
    }
    candidate["record_hash"] = _compute_hash(candidate)

    with _exclusive_lock(journal_path):
        if journal_path.exists():
            rows = _load_rows(journal_path)
            if _event_payload(rows[0]) != _event_payload(candidate):
                raise ConflictError("transaction identity conflict")
            return _status_object(rows)
        _append_row(journal_path, candidate)
        return _status_object([candidate])


def transition(
    journal: str | os.PathLike[str],
    transaction_id: str,
    event_id: str,
    from_state: str,
    state: str,
    timestamp: str,
    external_id: str | None = None,
    observation_digest: str | None = None,
) -> dict[str, Any]:
    """Append one state transition or idempotently re-submit its exact event."""

    journal_path = _journal_path(journal)
    _validate_identifier(transaction_id, "transaction_id")
    _validate_identifier(event_id, "event_id")
    if from_state not in _STATES or state not in _STATES:
        raise JournalError("invalid transition state")
    _validate_timestamp(timestamp)
    if external_id is not None:
        _validate_identifier(external_id, "external_id")
    if observation_digest is not None:
        _validate_digest(observation_digest)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sequence": 0,
        "previous_hash": "",
        "record_hash": "",
        "event_id": event_id,
        "event_type": "transition",
        "transaction_id": transaction_id,
        "from_state": from_state,
        "state": state,
        "timestamp": timestamp,
    }
    if external_id is not None:
        payload["external_id"] = external_id
    if observation_digest is not None:
        payload["observation_digest"] = observation_digest

    with _exclusive_lock(journal_path):
        rows = _load_rows(journal_path)
        if rows[0]["transaction_id"] != transaction_id:
            raise ConflictError("transaction identity conflict")
        for existing in rows[1:]:
            if existing["event_id"] == event_id:
                if _event_payload(existing) == _event_payload(payload):
                    return _status_object(rows)
                raise ConflictError("event identity conflict")
        current_state = rows[-1]["state"]
        _check_transition(
            current_state,
            from_state,
            state,
            external_id,
            observation_digest,
        )
        row = dict(payload)
        row["sequence"] = len(rows)
        row["previous_hash"] = rows[-1]["record_hash"]
        row["record_hash"] = _compute_hash(row)
        _append_row(journal_path, row)
        return _status_object([*rows, row])


def verify(journal: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify the complete journal and return deterministic value-free status."""

    journal_path = _journal_path(journal)
    with _exclusive_lock(journal_path):
        rows = _load_rows(journal_path)
    result = _status_object(rows)
    result["verified"] = True
    return result


def status(journal: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and return deterministic value-free status."""

    journal_path = _journal_path(journal)
    with _exclusive_lock(journal_path):
        return _status_object(_load_rows(journal_path))


# Explicit aliases keep the importable API readable for callers that prefer a
# command-shaped name while the CLI continues to use the short subcommands.
init_transaction = initialize
apply_transition = transition


def _json_output(value: Mapping[str, Any]) -> str:
    return _canonical_bytes(value).decode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release_transaction.py")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init")
    init_parser.add_argument("--journal", required=True)
    init_parser.add_argument("--transaction-id", required=True)
    init_parser.add_argument("--channel", required=True, choices=("beta", "stable"))
    init_parser.add_argument("--source-sha", required=True)
    init_parser.add_argument("--artifact-digest", required=True)
    init_parser.add_argument("--intent-digest", required=True)
    init_parser.add_argument("--timestamp", required=True)

    transition_parser = commands.add_parser("transition")
    transition_parser.add_argument("--journal", required=True)
    transition_parser.add_argument("--transaction-id", required=True)
    transition_parser.add_argument("--event-id", required=True)
    transition_parser.add_argument("--from", dest="from_state", required=True)
    transition_parser.add_argument("--to", dest="state", required=True)
    transition_parser.add_argument("--timestamp", required=True)
    transition_parser.add_argument("--external-id")
    transition_parser.add_argument("--observation-digest")

    for command in ("verify", "status"):
        command_parser = commands.add_parser(command)
        command_parser.add_argument("--journal", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "init":
            result = initialize(
                args.journal,
                args.transaction_id,
                args.channel,
                args.source_sha,
                args.artifact_digest,
                args.intent_digest,
                args.timestamp,
            )
        elif args.command == "transition":
            result = transition(
                args.journal,
                args.transaction_id,
                args.event_id,
                args.from_state,
                args.state,
                args.timestamp,
                args.external_id,
                args.observation_digest,
            )
        elif args.command == "verify":
            result = verify(args.journal)
        elif args.command == "status":
            result = status(args.journal)
        else:  # pragma: no cover - argparse enforces the command set.
            raise JournalError("invalid command")
        sys.stdout.write(_json_output(result) + "\n")
        return 0
    except JournalError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except (OSError, TypeError, ValueError, OverflowError):
        # Do not echo paths, argument values, or low-level platform messages.
        sys.stderr.write("error: operation failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
