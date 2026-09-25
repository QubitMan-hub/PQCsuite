import json
from pathlib import Path

from . import pack
from .elders import CATALOG

CONFIGS = [("full pack", {}), ("no second look", {"second_look": False}), ("no den (raw scouts)", {"raw": True})]


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


def main(corpus, truth_path=None):
    corpus = Path(corpus)
    truth_path = Path(truth_path) if truth_path else corpus.parent / "truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    print(f"corpus {corpus}  labelled pairs {sum(len(v) for v in truth.values())}\n")
    print(f"{'configuration':<22}{'precision':>10}{'recall':>9}{'F1':>7}{'FP':>5}{'FN':>5}")
    detail = []
    for name, kw in CONFIGS:
        r = pack.run(corpus, corpus.name, **kw)
        p, rc, f1, fp, fn = score(r, truth)
        print(f"{name:<22}{p:>10.3f}{rc:>9.3f}{f1:>7.3f}{len(fp):>5}{len(fn):>5}")
        detail.append((name, fp, fn))
    for name, fp, fn in detail:
        if fp or fn:
            print(f"\n{name}")
            for f, a in fp:
                print(f"  FP  {f}  {a}")
            for f, a in fn:
                print(f"  FN  {f}  {a}")
    return 0
