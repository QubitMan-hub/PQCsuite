import json
from pathlib import Path

from . import pipeline
from .catalog import CATALOG



def family(a):
    return CATALOG[a].family if a in CATALOG else a


def score(result, truth):
    found = {(s.file, family(s.algo)) for s in result.detections if s.verdict == "accepted" and not s.file.startswith("tls://")}
    gold = {(f, a) for f, algos in truth.items() for a in algos}
    tp, fp, fn = found & gold, found - gold, gold - found
    p = len(tp) / len(found) if found else 1.0
    r = len(tp) / len(gold) if gold else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1, sorted(fp), sorted(fn)


def main(corpus, truth_path=None, json_path=None):
    """Score the pipeline on a labelled corpus at (file, algorithm family) granularity: the quality gate's measurement."""
    corpus = Path(corpus)
    truth = json.loads(Path(truth_path or corpus.parent / "truth.json").read_text())
    p, rc, f1, fp, fn = score(pipeline.run(corpus, corpus.name), truth)
    row = {"precision": round(p, 3), "recall": round(rc, 3), "f1": round(f1, 3), "false_positives": len(fp), "false_negatives": len(fn), "pairs": sum(len(v) for v in truth.values())}
    print(f"precision {row['precision']:.3f}  recall {row['recall']:.3f}  F1 {row['f1']:.3f}  FP {len(fp)}  FN {len(fn)}  ({row['pairs']} labelled pairs)")
    for kind, items in (("false positive", fp), ("false negative", fn)):
        for item in sorted(items):
            print(f"  {kind}: {item}")
    if json_path:
        Path(json_path).write_text(json.dumps(row, indent=1) + "\n")
    return row
