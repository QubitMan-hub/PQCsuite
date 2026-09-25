import json
from pathlib import Path

from . import pack
from .elders import CATALOG

CONFIGS = [
    ("full pack", ()),
    ("without den", ("den",)),
    ("without corroboration", ("corroboration",)),
    ("without second look", ("second-look",)),
    ("  without flow", ("flow",)),
    ("  without registries", ("registries",)),
    ("  without siblings", ("siblings",)),
    ("without propagation", ("propagation",)),
    ("without source scouts", ("source",)),
    ("without config scouts", ("config",)),
    ("without artifact scouts", ("artifacts",)),
    ("without binary scouts", ("binary",)),
]


def family(a):
    return CATALOG[a].family if a in CATALOG else a


def score(result, truth):
    found = {(s.file, family(s.algo)) for s in result.sightings if s.verdict == "accepted" and not s.file.startswith("tls://")}
    gold = {(f, a) for f, algos in truth.items() for a in algos}
    tp, fp, fn = found & gold, found - gold, gold - found
    p = len(tp) / len(found) if found else 1.0
    r = len(tp) / len(gold) if gold else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1, sorted(fp), sorted(fn)


def main(corpus, truth_path=None, detail=False, json_path=None):
    corpus = Path(corpus)
    truth_path = Path(truth_path) if truth_path else corpus.parent / "truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    print(f"corpus {corpus}  labelled pairs {sum(len(v) for v in truth.values())}\n")
    print(f"{'configuration':<26}{'precision':>10}{'recall':>9}{'F1':>7}{'FP':>5}{'FN':>5}")
    rows = []
    for name, off in CONFIGS:
        r = pack.run(corpus, corpus.name, roles=pack.Roles.without(*off))
        p, rc, f1, fp, fn = score(r, truth)
        print(f"{name:<26}{p:>10.3f}{rc:>9.3f}{f1:>7.3f}{len(fp):>5}{len(fn):>5}")
        rows.append({"configuration": name.strip(), "without": list(off), "precision": round(p, 3), "recall": round(rc, 3), "f1": round(f1, 3),
                     "fp": fp, "fn": fn})
    for row in rows if detail else []:
        if row["fp"] or row["fn"]:
            print(f"\n{row['configuration']}")
            for f, a in row["fp"]:
                print(f"  FP  {f}  {a}")
            for f, a in row["fn"]:
                print(f"  FN  {f}  {a}")
    if json_path:
        Path(json_path).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0
