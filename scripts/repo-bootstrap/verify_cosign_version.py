#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

MAX_INPUT_BYTES = 64 * 1024


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: verify_cosign_version.py EXPECTED_VERSION", file=sys.stderr)
        return 2

    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print("cosign version output is oversized", file=sys.stderr)
        return 1

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("cosign version output is not valid UTF-8 JSON", file=sys.stderr)
        return 1

    expected = arguments[0]
    actual = payload.get("gitVersion") if isinstance(payload, dict) else None
    if actual != expected:
        print(f"expected cosign {expected}, got {actual!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
