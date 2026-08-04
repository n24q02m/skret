#!/usr/bin/env python3
"""Per-language package registry README field check (Spec A enforcement).

Detects language(s) from manifest presence and asserts:
- Python (pyproject.toml): [project] readme = "README.md"
- TS (package.json): repository field = github.com/n24q02m/<repo>.git
- Go (Dockerfile): LABEL org.opencontainers.image.source=...
- Rust (Cargo.toml): [package] readme = "README.md"
- Universal: README.md exists with non-empty tagline (line 3)
- MCP server (server.json): description matches README tagline

Run from any repo's working directory:
    python verify_readme_sync.py [--repo-root=.]

Returns exit 0 if all checks pass, 1 if any FAIL, 2 if no manifest detected.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib import (  # type: ignore[import-not-found]
    CheckResult,
    extract_readme_tagline,
    has_failure,
    normalize_for_match,
    render_results,
)


# ---------------------------------------------------------------------------
# Per-language checks
# ---------------------------------------------------------------------------


def check_python_readme_field(repo_root: Path) -> CheckResult:
    pp = repo_root / "pyproject.toml"
    if not pp.exists():
        return CheckResult("Python", "pyproject_readme_field", "SKIP", "No pyproject.toml")
    try:
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
    except Exception as e:
        return CheckResult(
            "Python", "pyproject_readme_field", "FAIL", f"Could not parse pyproject.toml: {e}",
        )
    project = data.get("project") or {}
    readme = project.get("readme")
    if isinstance(readme, str) and readme.lower() == "readme.md":
        return CheckResult("Python", "pyproject_readme_field", "PASS", f'readme = "{readme}"')
    if isinstance(readme, dict) and (readme.get("file") or "").lower() == "readme.md":
        return CheckResult(
            "Python", "pyproject_readme_field", "PASS",
            f'readme.file = "{readme.get("file")}"',
        )
    return CheckResult(
        "Python", "pyproject_readme_field", "FAIL",
        f'[project] readme should be "README.md" (got: {readme})',
        evidence={"readme": readme},
    )


def check_ts_repository_field(repo_root: Path) -> CheckResult:
    pkg = repo_root / "package.json"
    if not pkg.exists():
        return CheckResult("TypeScript", "package_repository_field", "SKIP", "No package.json")
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return CheckResult(
            "TypeScript", "package_repository_field", "FAIL", f"package.json invalid: {e}",
        )
    repo = data.get("repository")
    repo_url = ""
    if isinstance(repo, str):
        repo_url = repo
    elif isinstance(repo, dict):
        repo_url = repo.get("url", "")
    if "github.com/n24q02m/" in repo_url or "github.com:n24q02m/" in repo_url:
        return CheckResult("TypeScript", "package_repository_field", "PASS", repo_url)
    return CheckResult(
        "TypeScript", "package_repository_field", "FAIL",
        f"repository.url should reference github.com/n24q02m/<repo> (got: {repo_url})",
        evidence={"repository": repo},
    )


def check_go_dockerfile_ghcr_label(repo_root: Path) -> CheckResult:
    df = repo_root / "Dockerfile"
    if not df.exists():
        return CheckResult("Go/Docker", "dockerfile_ghcr_label", "SKIP", "No Dockerfile")
    text = df.read_text(encoding="utf-8")
    if re.search(r"LABEL\s+org\.opencontainers\.image\.source\s*=\s*[\"']?https://github\.com/n24q02m/", text):
        return CheckResult(
            "Go/Docker", "dockerfile_ghcr_label", "PASS",
            "LABEL org.opencontainers.image.source set",
        )
    return CheckResult(
        "Go/Docker", "dockerfile_ghcr_label", "FAIL",
        "Dockerfile missing 'LABEL org.opencontainers.image.source=https://github.com/n24q02m/...'",
    )


def check_rust_cargo_readme(repo_root: Path) -> CheckResult:
    ct = repo_root / "Cargo.toml"
    if not ct.exists():
        return CheckResult("Rust", "cargo_readme_field", "SKIP", "No Cargo.toml")
    try:
        data = tomllib.loads(ct.read_text(encoding="utf-8"))
    except Exception as e:
        return CheckResult("Rust", "cargo_readme_field", "FAIL", f"Cargo.toml invalid: {e}")
    pkg = data.get("package") or {}
    readme = pkg.get("readme")
    if isinstance(readme, str) and readme.lower() == "readme.md":
        return CheckResult("Rust", "cargo_readme_field", "PASS", f'readme = "{readme}"')
    return CheckResult(
        "Rust", "cargo_readme_field", "FAIL",
        f'[package] readme should be "README.md" (got: {readme})',
        evidence={"readme": readme},
    )


# ---------------------------------------------------------------------------
# Universal checks
# ---------------------------------------------------------------------------


def check_readme_exists(repo_root: Path) -> CheckResult:
    rd = repo_root / "README.md"
    if not rd.exists():
        return CheckResult("Universal", "readme_exists", "FAIL", "README.md missing at repo root")
    if rd.stat().st_size == 0:
        return CheckResult("Universal", "readme_exists", "FAIL", "README.md is empty")
    return CheckResult(
        "Universal", "readme_exists", "PASS", f"README.md ({rd.stat().st_size} bytes)",
    )


def check_readme_tagline(repo_root: Path) -> CheckResult:
    rd = repo_root / "README.md"
    if not rd.exists():
        return CheckResult("Universal", "readme_tagline_present", "SKIP", "README missing")
    text = rd.read_text(encoding="utf-8")
    tagline = extract_readme_tagline(text)
    if tagline and len(tagline) >= 10:
        return CheckResult(
            "Universal", "readme_tagline_present", "PASS",
            f"Tagline: {tagline[:60]}...",
        )
    return CheckResult(
        "Universal", "readme_tagline_present", "FAIL",
        "No substantive tagline found (need ≥10 chars on first prose line)",
    )


# ---------------------------------------------------------------------------
# MCP-server-specific check
# ---------------------------------------------------------------------------


def check_mcp_server_description_matches(repo_root: Path) -> CheckResult:
    sj = repo_root / "server.json"
    if not sj.exists():
        return CheckResult("MCP", "server_json_description_matches", "SKIP", "Not an MCP server")
    rd = repo_root / "README.md"
    if not rd.exists():
        return CheckResult("MCP", "server_json_description_matches", "SKIP", "README missing")
    try:
        sj_data = json.loads(sj.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return CheckResult("MCP", "server_json_description_matches", "FAIL", f"server.json invalid: {e}")
    desc = (sj_data.get("description") or "").strip()
    if not desc:
        return CheckResult(
            "MCP", "server_json_description_matches", "FAIL",
            "server.json has empty description",
        )
    tagline = extract_readme_tagline(rd.read_text(encoding="utf-8"))
    if not tagline:
        return CheckResult(
            "MCP", "server_json_description_matches", "SKIP",
            "Cannot extract README tagline",
        )
    if normalize_for_match(desc) == normalize_for_match(tagline):
        return CheckResult(
            "MCP", "server_json_description_matches", "PASS",
            "server.json description matches README tagline",
        )
    return CheckResult(
        "MCP", "server_json_description_matches", "FAIL",
        f"server.json description != README tagline",
        evidence={"server_json_description": desc, "readme_tagline": tagline},
    )


# ---------------------------------------------------------------------------
# Detection + main
# ---------------------------------------------------------------------------


def detect_languages(repo_root: Path) -> list[str]:
    langs: list[str] = []
    if (repo_root / "pyproject.toml").exists():
        langs.append("python")
    if (repo_root / "package.json").exists():
        langs.append("typescript")
    if (repo_root / "Cargo.toml").exists():
        langs.append("rust")
    if (repo_root / "go.mod").exists():
        langs.append("go")
    if (repo_root / "Dockerfile").exists() and "go" not in langs:
        langs.append("go")  # GHCR LABEL applies to all GHCR-publishing repos
    return langs


def run_checks(repo_root: Path, langs: list[str] | None = None) -> list[CheckResult]:
    results: list[CheckResult] = []
    detected = langs if langs else detect_languages(repo_root)

    # Universal first
    results.append(check_readme_exists(repo_root))
    results.append(check_readme_tagline(repo_root))

    # Per-language
    if "python" in detected:
        results.append(check_python_readme_field(repo_root))
    if "typescript" in detected:
        results.append(check_ts_repository_field(repo_root))
    if "go" in detected:
        results.append(check_go_dockerfile_ghcr_label(repo_root))
    if "rust" in detected:
        results.append(check_rust_cargo_readme(repo_root))

    # MCP server (always check if server.json present)
    results.append(check_mcp_server_description_matches(repo_root))
    return results


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Per-language registry README field check")
    p.add_argument("--repo-root", default=".", help="Local repo root (default cwd)")
    p.add_argument(
        "--lang",
        choices=["auto", "python", "typescript", "go", "rust", "all"],
        default="auto",
        help="Target language (default: auto-detect from manifests)",
    )
    p.add_argument("--format", default="table", choices=["json", "table", "markdown"])
    p.add_argument("--output-file")
    return p.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"ERROR: --repo-root {repo_root} does not exist", file=sys.stderr)
        return 2

    if args.lang == "auto":
        langs = detect_languages(repo_root)
    elif args.lang == "all":
        langs = ["python", "typescript", "go", "rust"]
    else:
        langs = [args.lang]

    if not langs and args.lang == "auto":
        print(
            "WARNING: no recognizable manifest (pyproject.toml, package.json, "
            "Cargo.toml, go.mod, Dockerfile) found at repo root",
            file=sys.stderr,
        )
        # Still run universal checks
        results = run_checks(repo_root, langs=[])
    else:
        results = run_checks(repo_root, langs=langs)

    output = render_results(results, args.format)
    if args.output_file:
        Path(args.output_file).write_text(output, encoding="utf-8")
    else:
        print(output)

    return 1 if has_failure(results) else 0


if __name__ == "__main__":
    sys.exit(main())
