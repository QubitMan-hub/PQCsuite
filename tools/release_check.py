"""Gate a release: python tools/release_check.py TAG

The tag (core-v1.0.0, tls-v1.0.0, readiness-v1.0.0) must match the version in that package's pyproject.toml and a heading in
its CHANGELOG.md, and a product's acxelin-core range must include a core version that was already released (a core-v* tag).
"""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = {"core": ROOT / "core", "tls": ROOT / "products/tls", "readiness": ROOT / "products/readiness"}


def parse_tag(tag):
    m = re.fullmatch(r"(?:refs/tags/)?(core|tls|readiness)-v(\d+\.\d+\.\d+)", tag)
    if not m:
        raise ValueError(f"{tag!r} is not a release tag: use core-vX.Y.Z, tls-vX.Y.Z or readiness-vX.Y.Z")
    return m.group(1), m.group(2)


def check(product, version, tags):
    folder = FOLDERS[product]
    project = tomllib.loads((folder / "pyproject.toml").read_text())["project"]
    if project["version"] != version:
        raise ValueError(f"the tag says {version} but {folder.name}/pyproject.toml says {project['version']}")
    changelog = folder / "CHANGELOG.md"
    if product != "core" and not re.search(rf"^## {re.escape(version)}\b", changelog.read_text(), re.M):
        raise ValueError(f"{changelog.relative_to(ROOT)} has no '## {version}' section")
    if product == "core":
        return f"acxelin-core {version}"
    spec = next(SpecifierSet(d.split("acxelin-core", 1)[1]) for d in project["dependencies"] if d.startswith("acxelin-core"))
    released = sorted((Version(t.removeprefix("core-v")) for t in tags if re.fullmatch(r"core-v\d+\.\d+\.\d+", t)), reverse=True)
    match = next((v for v in released if v in spec), None)
    if match is None:
        raise ValueError(f"{project['name']} needs acxelin-core{spec}, and there is no released acxelin-core in that range: release core first")
    return f"acxelin-core {match}"


if __name__ == "__main__":
    product, version = parse_tag(sys.argv[1])
    tags = subprocess.run(["git", "tag", "--list", "core-v*"], capture_output=True, text=True, check=True, cwd=ROOT).stdout.split()
    print(f"{product} {version}: ok, built against {check(product, version, tags)}")
