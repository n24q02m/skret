"""Shared utilities for the local repo-bootstrap README sync gate.

Pure stdlib only (Python 3.13+). This is the minimal helper surface used by
verify_readme_sync.py and does not depend on the private repo-bootstrap tree.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class CheckResult:
    group: str
    name: str
    status: str
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def format_table(results: list[CheckResult]) -> str:
    """Render check results as the canonical ASCII table."""
    by_group: dict[str, list[CheckResult]] = {}
    for result in results:
        by_group.setdefault(result.group, []).append(result)

    lines: list[str] = []
    lines.append("=" * 88)
    lines.append(f"{'Group':<20} {'Check':<40} {'Status':<6} Message")
    lines.append("-" * 88)
    for group in by_group:
        for result in by_group[group]:
            message = result.message[:35] + "..." if len(result.message) > 38 else result.message
            lines.append(f"{result.group:<20} {result.name:<40} {result.status:<6} {message}")
    lines.append("-" * 88)
    summary = _summarize(results)
    lines.append(f"Summary: {summary['PASS']} PASS / {summary['FAIL']} FAIL / {summary['SKIP']} SKIP")
    lines.append("=" * 88)
    return "\n".join(lines)


def format_json(results: list[CheckResult]) -> str:
    payload = {
        "summary": _summarize(results),
        "results": [
            {
                "group": result.group,
                "name": result.name,
                "status": result.status,
                "message": result.message,
                "evidence": result.evidence,
            }
            for result in results
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def format_markdown(results: list[CheckResult]) -> str:
    """Render GitHub-flavored markdown for PR bodies or issues."""
    summary = _summarize(results)
    lines = [
        f"## Repo audit — {summary['PASS']} PASS / {summary['FAIL']} FAIL / {summary['SKIP']} SKIP",
        "",
    ]
    by_group: dict[str, list[CheckResult]] = {}
    for result in results:
        by_group.setdefault(result.group, []).append(result)
    for group, items in by_group.items():
        lines.append(f"### {group}")
        lines.append("")
        lines.append("| Check | Status | Message |")
        lines.append("|---|---|---|")
        for result in items:
            icon = {"PASS": "OK", "FAIL": "FAIL", "SKIP": "skip"}.get(result.status, result.status)
            message = (result.message or "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{result.name}` | {icon} | {message} |")
        lines.append("")
    return "\n".join(lines)


def _summarize(results: list[CheckResult]) -> dict[str, int]:
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts


_RST_ADORNMENT = re.compile(r"^[=\-~^\"'`*+#_:.]{3,}\s*$")


def _extract_rst_tagline(text: str) -> str | None:
    """Tagline from a reStructuredText README."""
    lines = text.splitlines()
    paragraphs: list[list[str]] = []
    current: list[str] = []
    in_directive = False
    headings_seen = 0

    for i, raw in enumerate(lines):
        stripped = raw.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if _RST_ADORNMENT.match(stripped):
            continue
        if stripped and _RST_ADORNMENT.match(nxt):
            headings_seen += 1
            if headings_seen > 1:
                break
            current.clear()
            continue
        if stripped.startswith(".."):
            in_directive = True
            if current:
                paragraphs.append(current)
                current = []
            continue
        if not stripped:
            if current:
                paragraphs.append(current)
                current = []
            continue
        if in_directive:
            if raw[:1].isspace():
                continue
            in_directive = False
        current.append(stripped)
    if current:
        paragraphs.append(current)

    for paragraph in paragraphs:
        joined = " ".join(paragraph)
        cleaned = re.sub(r"`([^`<]+?)(?:\s*<[^>]+>)?`_{0,2}", r"\1", joined)
        cleaned = re.sub(r"``([^`]+)``", r"\1", cleaned)
        cleaned = re.sub(r"\*{1,2}([^*]+?)\*{1,2}", r"\1", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if len(cleaned) >= 10:
            return cleaned
    return None


def extract_readme_tagline(readme_text: str, *, filename: str = "README.md") -> str | None:
    """Best-effort extract of the first substantive hero tagline."""
    if not filename.lower().endswith(".md"):
        return _extract_rst_tagline(readme_text)
    text = re.sub(
        r"<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->.*?<!-- END: AUTO-GENERATED-CROSS-PROMO -->",
        "", readme_text, flags=re.DOTALL,
    )
    text = re.sub(r"<details\b.*?</details>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.split(r"^##\s+", text, maxsplit=1, flags=re.MULTILINE)[0]
    text = re.sub(r"<h1\b[^>]*>.*?</h1>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"^#\s+.*$", "", text, flags=re.MULTILINE)

    metadata_prefixes = (
        "mcp-name:", "version:", "license:", "homepage:", "author:",
        "name:", "description:", "type:",
    )

    def clean_line(raw: str) -> str:
        cleaned = re.sub(r"^\s*>\s*", "", raw)
        cleaned = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", cleaned)
        cleaned = re.sub(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)", " ", cleaned)
        cleaned = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cleaned)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"\*+([^*]+?)\*+", r"\1", cleaned)
        cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
        return re.sub(r"\s+", " ", cleaned).strip()

    def is_metadata(line: str) -> bool:
        low = line.strip().lower()
        return any(low.startswith(prefix) for prefix in metadata_prefixes)

    def is_list_or_quote(line: str) -> bool:
        stripped = line.strip()
        if stripped.startswith((">", "> ")) and re.search(r"\*\*[^*]+?\*\*|<strong>", stripped):
            return False
        return stripped.startswith(("- ", "* ", "+ ", "> ", ">"))

    def is_table_row(line: str) -> bool:
        return line.strip().startswith("|")

    paragraphs: list[tuple[str, bool]] = []
    current: list[str] = []
    in_code_fence = False
    seen_fence = False

    def flush() -> None:
        if current:
            paragraphs.append((" ".join(current), not seen_fence))
            current.clear()

    for raw_line in text.splitlines():
        if raw_line.strip().startswith("```"):
            flush()
            in_code_fence = not in_code_fence
            seen_fence = True
            continue
        if in_code_fence:
            continue
        if not raw_line.strip():
            flush()
            continue
        if is_metadata(raw_line) or is_list_or_quote(raw_line) or is_table_row(raw_line):
            flush()
            continue
        current.append(raw_line)
    flush()

    bold_re = re.compile(r"(?:<strong>.+?</strong>|\*\*.+?\*\*)", re.DOTALL)
    for paragraph, _ in paragraphs:
        if not bold_re.search(paragraph):
            continue
        cleaned = clean_line(paragraph)
        if cleaned and len(cleaned) >= 10:
            return cleaned

    for paragraph, before_fence in paragraphs:
        if not before_fence:
            break
        cleaned = clean_line(paragraph)
        if cleaned and len(cleaned) >= 10:
            return cleaned
    return None


def normalize_for_match(text: str) -> str:
    """Lower-case, strip trailing punctuation, and collapse whitespace."""
    return re.sub(r"\s+", " ", text.strip().rstrip(".!?").lower())


def render_results(results: list[CheckResult], fmt: str) -> str:
    if fmt == "json":
        return format_json(results)
    if fmt == "markdown":
        return format_markdown(results)
    return format_table(results)


def has_failure(results: Iterable[CheckResult]) -> bool:
    return any(result.status == "FAIL" for result in results)
