import tomllib
from pathlib import Path

import acxelin_readiness
from acxelin_readiness import cbom


def test_the_version_in_code_is_the_packaged_version_and_reaches_the_cbom():
    packaged = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())["project"]["version"]
    assert acxelin_readiness.__version__ == packaged
    bom = cbom.build("p", [], [], [], [])
    assert bom["metadata"]["tools"]["components"][0]["version"] == packaged


def test_the_crawler_extra_excludes_tree_sitter_0_26():
    """tree-sitter 0.26.0's binding segfaults building a node's child list (node.c:447) partway through scanning real Go and
    JavaScript repositories (go-jose, forge); 0.25.2 scans them cleanly. Lift the bound only after the real-world CI job passes."""
    from packaging.specifiers import SpecifierSet
    extra = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())["project"]["optional-dependencies"]["crawler"]
    spec = SpecifierSet(next(d for d in extra if d.startswith("tree-sitter>")).removeprefix("tree-sitter"))
    assert "0.25.2" in spec and "0.26.0" not in spec
