import json
import sys
import urllib.request
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/"
NAMES = ["bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"]
CACHE = Path(__file__).resolve().parent.parent / ".cache" / "schemas"


def schemas():
    CACHE.mkdir(parents=True, exist_ok=True)
    out = {}
    for n in NAMES:
        p = CACHE / n
        if not p.exists():
            urllib.request.urlretrieve(BASE + n, p)
        out[n] = json.loads(p.read_text(encoding="utf-8"))
    return out


def main(path):
    if not Path(path).is_file():
        print(f"{path} not found: run `wolfpack scan PATH` first, or give the CBOM to check")
        return 1
    s = schemas()
    reg = Registry()
    for n, doc in s.items():
        r = Resource.from_contents(doc, default_specification=DRAFT7)
        reg = reg.with_resource(n, r)
        if "$id" in doc:
            reg = reg.with_resource(doc["$id"], r)
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    errs = list(Draft7Validator(s["bom-1.6.schema.json"], registry=reg).iter_errors(bom))
    for e in errs[:20]:
        print(list(e.path), e.message[:200])
    print(f"{path}: {len(errs)} schema errors")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "wolfpack-out/cbom.json"))
