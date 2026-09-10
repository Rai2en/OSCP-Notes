"""Check inline Markdown links to local files (not remote URLs or heading anchors)."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+\"[^\"]*\")?\s*\)")


def prose_lines(text):
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            continue
        if fence is None:
            yield re.sub(r"`+[^`]*`+", "", line)


def check_documents(root):
    root = Path(root).resolve()
    errors = []
    paths = [root / "README.md", root / "CONTRIBUTING.md"]
    for folder in ("docs", "templates"):
        paths.extend(sorted((root / folder).rglob("*.md")))
    for path in paths:
        if not path.exists():
            continue
        for line in prose_lines(path.read_text(encoding="utf-8")):
            for match in LINK.finditer(line):
                href = match.group(1) or match.group(2)
                url = urlsplit(href)
                if url.scheme or url.netloc or not url.path:
                    continue
                target = (path.parent / unquote(url.path)).resolve()
                if target != root and root not in target.parents:
                    errors.append(f"{path.relative_to(root)}: link escapes repository: {href}")
                elif not target.exists():
                    errors.append(f"{path.relative_to(root)}: missing file: {href}")
    return errors


if __name__ == "__main__":
    problems = check_documents(Path(__file__).resolve().parents[1])
    print("\n".join(problems) if problems else "Local Markdown file links OK.")
    raise SystemExit(bool(problems))
