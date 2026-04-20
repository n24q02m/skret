"""Inject Starlight-compatible frontmatter (title, description) into migrated
Markdown pages. Reads the first H1 heading and the first paragraph to derive
the fields. Idempotent: skips files that already have a YAML frontmatter block.

Usage:
    python scripts/migrate-frontmatter.py docs/src/content/docs
"""

import re
import sys
from pathlib import Path


def first_paragraph(body: str) -> str:
    for chunk in body.split("\n\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.startswith("#"):
            continue
        if chunk.startswith(("|", "-", "*", ">", "```")):
            continue
        one_line = " ".join(chunk.split())
        return one_line[:160]
    return ""


def inject(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if text.startswith("---\n"):
        return False

    match = re.match(r"#\s+(.+?)\s*\n", text)
    if not match:
        print(f"  SKIP (no H1): {path}")
        return False

    title = match.group(1).strip()
    body_after_h1 = text[match.end():]
    desc = first_paragraph(body_after_h1)

    front = ["---", f"title: {title}"]
    if desc:
        escaped = desc.replace('"', '\\"')
        front.append(f'description: "{escaped}"')
    front.append("---")
    front_block = "\n".join(front) + "\n\n"

    # Drop the original H1 since Starlight renders the frontmatter title.
    new_body = body_after_h1.lstrip("\n")
    path.write_text(front_block + new_body, encoding="utf-8")
    print(f"  OK: {path}  ->  {title}")
    return True


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/src/content/docs")
    if not root.exists():
        raise SystemExit(f"not found: {root}")
    changed = 0
    for md in sorted(root.rglob("*.md")):
        if inject(md):
            changed += 1
    print(f"\nUpdated {changed} file(s).")


if __name__ == "__main__":
    main()
