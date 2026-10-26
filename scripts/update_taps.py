#!/usr/bin/env python3
"""Rewrite the skret Homebrew cask and Scoop manifest for one release.

The release publisher no longer pushes to the tap repositories, so the files
there are updated from the release's own ``checksums.txt``:

    update_taps.py --tag v1.36.0 --checksums checksums.txt \
        --cask homebrew-tap/Casks/skret.rb \
        --scoop scoop-bucket/bucket/skret.json

Only the version, the per-archive URL versions and the sha256 values change.
A tag, checksum file or target that does not match what the file already
expects fails closed and leaves the files untouched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TAG = re.compile(r"v(\d+\.\d+\.\d+)")
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64}) [ *](skret_\S+)")
CASK_VERSION = re.compile(r'^(\s*version\s+)"[^"]+"', re.MULTILINE)
CASK_ASSET = re.compile(
    r'(sha256\s+)"[0-9a-f]{64}"(\s+url\s+"[^"]*/skret_#\{version\}_([a-z0-9_]+\.tar\.gz)")'
)


def parse_tag(tag: str) -> str:
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"not a stable release tag: {tag!r}")
    return match.group(1)


def parse_checksums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_LINE.fullmatch(line.strip())
        if match:
            sums[match.group(2)] = match.group(1)
    if not sums:
        raise ValueError("checksums file lists no skret archives")
    return sums


def update_cask(source: str, version: str, sums: dict[str, str]) -> str:
    updated, count = CASK_VERSION.subn(rf'\g<1>"{version}"', source, count=1)
    if count != 1:
        raise ValueError("cask has no version line")
    assets = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal assets
        name = f"skret_{version}_{match.group(3)}"
        if name not in sums:
            raise ValueError(f"checksums.txt has no entry for {name}")
        assets += 1
        return f'{match.group(1)}"{sums[name]}"{match.group(2)}'

    updated = CASK_ASSET.sub(replace, updated)
    if assets == 0:
        raise ValueError("cask lists no skret archives")
    return updated


def update_scoop(source: str, version: str, sums: dict[str, str]) -> str:
    manifest = json.loads(source)
    manifest["version"] = version
    architectures = manifest.get("architecture")
    if not architectures:
        raise ValueError("manifest lists no architectures")
    for arch, entry in architectures.items():
        name = f"skret_{version}_windows_{'amd64' if arch == '64bit' else arch}.zip"
        if name not in sums:
            raise ValueError(f"checksums.txt has no entry for {name}")
        entry["url"] = (
            f"https://github.com/n24q02m/skret/releases/download/v{version}/{name}"
        )
        entry["hash"] = sums[name]
    return json.dumps(manifest, indent=4) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--cask", type=Path, required=True)
    parser.add_argument("--scoop", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        version = parse_tag(args.tag)
        sums = parse_checksums(args.checksums.read_text(encoding="utf-8"))
        cask = update_cask(args.cask.read_text(encoding="utf-8"), version, sums)
        scoop = update_scoop(args.scoop.read_text(encoding="utf-8"), version, sums)
    except (OSError, ValueError) as error:
        print(f"update_taps: {error}", file=sys.stderr)
        return 1
    args.cask.write_text(cask, encoding="utf-8", newline="\n")
    args.scoop.write_text(scoop, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
