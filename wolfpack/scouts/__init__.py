import os
from pathlib import Path

from ..elders import CATALOG
from ..model import Sighting

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__", "dist", "build", "target", ".tox",
             "site-packages", ".idea", ".vscode", ".gradle", ".mypy_cache", ".pytest_cache", "bin", "obj", "wolfpack-out"}
TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__", "testdata", "test_data", "fixtures", "mocks", "examples", "example", "samples", "sample", "demo"}
BUILD_DIRS = {"dist", "build", "target", "bin", "obj"}
MAX_BYTES = 2_000_000


def iter_files(root, include_vendor=False, max_bytes=MAX_BYTES, skip=None):
    skip = SKIP_DIRS if skip is None else skip
    root = Path(root)
    if root.is_file():
        yield root
        return
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if include_vendor or x not in skip)
        for f in sorted(files):
            p = Path(d) / f
            try:
                if p.stat().st_size <= max_bytes:
                    yield p
            except OSError:
                continue


def rel(root, p):
    root = Path(root)
    try:
        return Path(p).relative_to(root if root.is_dir() else root.parent).as_posix()
    except ValueError:
        return Path(p).as_posix()


def is_test(relpath):
    parts = [x.lower() for x in Path(relpath).parts]
    name = parts[-1] if parts else ""
    return bool(TEST_PARTS & set(parts[:-1])) or name.startswith("test_") or any(
        name.endswith(s) for s in ("_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "test.java", "tests.cs", "_test.py", "_spec.rb"))


def read(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def carried_hashes(sightings):
    """A primitive parameterised with a hash (HMAC-SHA256, PBKDF2 over SHA-1, SHA256withRSA) also reports the hash itself."""
    have = {(s.file, s.line, s.algo) for s in sightings}
    out = []
    for s in sightings:
        h = s.params.get("hash")
        if h in CATALOG and h != s.algo and (s.file, s.line, h) not in have:
            have.add((s.file, s.line, h))
            params = {"role": f"hash of {s.algo}"} | ({"literal": s.params["literal"]} if "literal" in s.params else {})
            out.append(Sighting(algo=h, file=s.file, line=s.line, evidence=s.evidence, scout=s.scout, snippet=s.snippet, lang=s.lang,
                                params=params, context=set(s.context)))
    return out
