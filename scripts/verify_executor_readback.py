#!/usr/bin/env python3
"""Gate Hub deployment on an authenticated security-executor readback."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


READBACK_ENV = "SKRET_EXECUTOR_READBACK_JSON"
ORDER_MANIFEST = Path(__file__).resolve().parents[1] / "hub" / "deployment-order.json"
EXPECTED_BINDING = "EXECUTOR"
EXPECTED_READBACK = "verified"


def load_order_manifest() -> dict[str, Any] | None:
    try:
        manifest = json.loads(ORDER_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict):
        return None
    if (
        manifest.get("executor_readback_required_before_hub_ready") is not True
        or manifest.get("hub_ready_without_executor_readback") is not False
        or manifest.get("hub_deploy_allowed") is not False
        or manifest.get("source_only") is not True
        or manifest.get("required_deploy_order") != ["skret-security-executor", "skret-hub"]
    ):
        return None
    if not isinstance(manifest.get("executor_service"), str) or not isinstance(manifest.get("hub_worker"), str):
        return None
    return manifest


def verify_readback(raw: str | None, manifest: dict[str, Any] | None) -> bool:
    if manifest is None or raw is None or not raw.strip():
        return False
    try:
        readback = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(readback, dict):
        return False

    expected: dict[str, object] = {
        "executor_service": manifest["executor_service"],
        "hub_worker": manifest["hub_worker"],
        "binding": EXPECTED_BINDING,
        "ready": True,
        "readback": EXPECTED_READBACK,
        "hub_deploy_allowed": True,
    }
    for key, value in expected.items():
        actual = readback.get(key)
        if type(actual) is not type(value) or actual != value:
            return False
    return True


def main() -> int:
    if not verify_readback(os.environ.get(READBACK_ENV), load_order_manifest()):
        print("executor readback required", file=sys.stderr)
        return 78
    print("executor readback verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
