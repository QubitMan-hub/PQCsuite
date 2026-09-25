"""Compares Wolf Pack and CBOMkit at (file, algorithm family) granularity on the languages CBOMkit supports."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from wolfpack.elders import CATALOG, lookup, pq_from_text
from wolfpack.scouts import is_test

CBOMKIT_LANGS = {".java", ".py", ".go", ".cs"}


def family(name):
    """Family of a CBOMkit component name such as "AES-128-GCM", "ECDSA-SHA-256" or "EC-secp256r1"."""
    toks = name.split("-")
    for k in range(len(toks), 0, -1):
        a = lookup("-".join(toks[:k])) or pq_from_text("-".join(toks[:k]))
        if a:
            return CATALOG[a].family
    return name


def resolve(loc, root):
    """CBOMkit sometimes prefixes locations with the module folder name; strip leading parts until the file exists."""
    parts = Path(loc).parts
    for k in range(len(parts)):
        if (root / Path(*parts[k:])).is_file():
            return Path(*parts[k:]).as_posix()
    return Path(loc).as_posix()


def keep(f, tests):
    return Path(f).suffix.lower() in CBOMKIT_LANGS and (tests or not is_test(f))


def cbomkit_pairs(path, root, tests):
    out = set()
    for c in json.loads(Path(path).read_text(encoding="utf-8")).get("components", []):
        if (c.get("cryptoProperties") or {}).get("assetType") not in ("algorithm", "protocol"):
            continue
        for o in (c.get("evidence") or {}).get("occurrences", []):
            f = resolve(o["location"], root)
            if keep(f, tests):
                out.add((f, family(c["name"])))
    return out


def wolfpack_pairs(path, tests):
    out = set()
    for s in json.loads(Path(path).read_text(encoding="utf-8"))["sightings"]:
        if s["verdict"] == "accepted" and s["algo"] in CATALOG and keep(s["file"], tests):
            out.add((s["file"], CATALOG[s["algo"]].family))
    return out


def prf(found, gold):
    tp = found & gold
    p = len(tp) / len(found) if found else 1.0
    r = len(tp) / len(gold) if gold else 1.0
    return p, r, 2 * p * r / (p + r) if p + r else 0.0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", help="the scanned repository")
    ap.add_argument("--wolfpack", required=True, help="findings.json from wolfpack scan")
    ap.add_argument("--cbomkit", required=True, help="cbom.json from CBOMkit-action")
    ap.add_argument("--truth", help="labels as {file: [family, ...]}, same format as bench/truth.json")
    ap.add_argument("--tests", action="store_true", help="include test files (excluded by default)")
    ap.add_argument("--json", help="write the pair sets to this file")
    a = ap.parse_args(argv)
    root = Path(a.root)
    wp, ck = wolfpack_pairs(a.wolfpack, a.tests), cbomkit_pairs(a.cbomkit, root, a.tests)
    print(f"{root.name}: wolfpack {len(wp)} pairs, cbomkit {len(ck)} pairs, both {len(wp & ck)}, "
          f"wolfpack only {len(wp - ck)}, cbomkit only {len(ck - wp)}")
    if a.truth:
        truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
        gold = {(f, x) for f, xs in truth.items() for x in xs if keep(f, a.tests)}
        for name, found in (("wolfpack", wp), ("cbomkit", ck)):
            p, r, f1 = prf(found, gold)
            print(f"  {name:<9} precision {p:.3f}  recall {r:.3f}  F1 {f1:.3f}")
    for label, pairs in (("cbomkit only", ck - wp), ("wolfpack only", wp - ck)):
        for f, x in sorted(pairs):
            print(f"  {label:<14} {f}  {x}")
    if a.json:
        Path(a.json).write_text(json.dumps({"both": sorted(wp & ck), "wolfpack_only": sorted(wp - ck), "cbomkit_only": sorted(ck - wp)}, indent=1),
                                encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
