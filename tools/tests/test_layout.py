"""Each product stands alone, in its source and in its tests: core imports no product, a product imports no other product.
Read from the files, so an import that only works because everything is installed together still fails here."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OTHERS = {"acxelin_readiness", "acxelin_tls", "acxelin_vpn"}
OWN = {"core": None, "products/readiness": "acxelin_readiness", "products/tls": "acxelin_tls", "products/vpn": "acxelin_vpn"}


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            yield node.module.split(".")[0]


def test_no_folder_imports_another_product():
    wrong = []
    for folder, own in OWN.items():
        for path in sorted((ROOT / folder).rglob("*.py")):
            if {"build", "corpus", "examples"} & set(path.relative_to(ROOT / folder).parts):
                continue
            wrong += [f"{path.relative_to(ROOT)} imports {m}" for m in sorted(set(imports(path)) & (OTHERS - {own}))]
    assert wrong == []
