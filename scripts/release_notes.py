"""Prints the changelog section for a release, after checking the version matches the package.

    python scripts/release_notes.py . 0.1.0          # the suite: CHANGELOG.md, pyproject.toml
    python scripts/release_notes.py wolf-pack 1.1.0  # Wolf Pack: wolf-pack/CHANGELOG.md, wolf-pack/pyproject.toml
"""
import re
import sys
import tomllib
from pathlib import Path


def notes(folder, version):
    root = Path(__file__).resolve().parent.parent / folder
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if declared != version:
        raise SystemExit(f"the tag says {version} but {folder}/pyproject.toml says {declared}")
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(version)}\b[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m or not m.group(1).strip():
        raise SystemExit(f"{folder}/CHANGELOG.md has no '## {version}' section; rename 'Unreleased' to it first")
    return m.group(1).strip() + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(notes(sys.argv[1], sys.argv[2]), end="")
