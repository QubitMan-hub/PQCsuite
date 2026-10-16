import tomllib
from pathlib import Path

import acxelin_readiness
from acxelin_readiness import cbom


def test_the_version_in_code_is_the_packaged_version_and_reaches_the_cbom():
    packaged = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())["project"]["version"]
    assert acxelin_readiness.__version__ == packaged
    bom = cbom.build("p", [], [], [], [])
    assert bom["metadata"]["tools"]["components"][0]["version"] == packaged
