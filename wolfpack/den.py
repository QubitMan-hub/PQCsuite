import re
from collections import defaultdict
from pathlib import Path

from .elders import CATALOG, variant
from .model import Asset

BASE = {"string": 0.35, "import": 0.45, "identifier": 0.65, "binary": 0.8, "constant": 0.85, "call": 0.9, "config": 0.9, "artifact": 0.95, "live": 1.0}
RANK = {k: i for i, k in enumerate(BASE)}
KIN = {"ECC": "EC", "ECDSA": "EC", "ECDH": "EC"}
HARD = {"comment": "appears only inside a comment", "doc": "appears only in a docstring", "prose": "mentioned in human-readable text, not used"}
KEY_PARAMS = ("key_size", "curve", "mode", "hash", "padding")


def _kin(a):
    return KIN.get(a, a)


def dedupe(sightings):
    best = {}
    for s in sightings:
        k = (s.file, s.line, s.algo, "comment" in s.context)
        cur = best.setdefault(k, s)
        if cur is not s:
            win, lose = (s, cur) if RANK[s.evidence] > RANK[cur.evidence] else (cur, s)
            for p, v in lose.params.items():
                win.params.setdefault(p, v)
            best[k] = win
    return list(best.values())


class Lines:
    def __init__(self, root):
        self.root, self.cache = Path(root), {}

    def __call__(self, f):
        if f not in self.cache:
            p = self.root / f if self.root.is_dir() else self.root
            try:
                self.cache[f] = p.read_text(encoding="utf-8", errors="replace").splitlines() if "://" not in f and "!" not in f else []
            except OSError:
                self.cache[f] = []
        return self.cache[f]


def suppressed(s, lines):
    ls = lines(s.file)
    return any(0 < k <= len(ls) and "wolfpack:ignore" in ls[k - 1] for k in (s.line, s.line - 1))


def verify(sightings, threshold=0.6, lines=None, corroboration=True):
    """The den: every sighting gets a confidence from its evidence; only what clears the threshold enters the CBOM."""
    sightings = dedupe(sightings)
    by_file = defaultdict(list)
    for s in sightings:
        if lines and s.line and suppressed(s, lines):
            s.confidence, s.verdict, s.reason = 0.0, "suppressed", "suppressed with a wolfpack:ignore comment"
            continue
        hard = next((HARD[c] for c in ("comment", "doc", "prose") if c in s.context), None)
        if hard:
            s.confidence, s.verdict, s.reason = 0.0, "rejected", hard
            continue
        if s.algo not in CATALOG:
            s.confidence, s.verdict, s.reason = 0.0, "rejected", "unrecognised algorithm"
            continue
        s.confidence = BASE[s.evidence] + (0.05 if any(s.params.get(k) for k in KEY_PARAMS) else 0)
        by_file[s.file].append(s)
    for f, group in by_file.items():
        for s in group:
            others = [o for o in group if o is not s and _kin(o.algo) == _kin(s.algo) and o.evidence != s.evidence] if corroboration else []
            if others:
                s.confidence += 0.25
                s.reason = f"corroborated by {others[0].evidence} evidence on line {others[0].line}"
            s.confidence = round(min(s.confidence, 1.0), 2)
            if s.confidence >= threshold:
                s.verdict = "accepted"
                s.reason = s.reason or f"{s.evidence} evidence"
            else:
                s.verdict = "quarantined"
                s.reason = {"import": "imported, but no usage observed in this file",
                            "string": "algorithm name in a string literal with no observed use"}.get(s.evidence, "weak evidence")
    return sightings


def admit_all(sightings):
    """Ablation: the den is bypassed and every scout sighting of a known algorithm is trusted."""
    out = [s for s in sightings if s.algo in CATALOG]
    for s in out:
        s.verdict, s.confidence, s.reason = "accepted", 1.0, "den disabled (ablation)"
    return out


def assets(sightings):
    groups = defaultdict(list)
    for s in sightings:
        if s.verdict != "accepted":
            continue
        params = {k: v for k, v in s.params.items() if k in KEY_PARAMS and v}
        groups[variant(s.algo, params)].append((s, params))
    out = []
    for v, items in sorted(groups.items()):
        algo = items[0][0].algo
        params = {}
        for _, p in items:
            for k, val in p.items():
                params.setdefault(k, val)
        sl = [s for s, _ in items]
        out.append(Asset(ref=f"crypto/{re.sub(r'[^A-Za-z0-9.-]+', '-', v)}", algo=algo, variant=v, params=params, sightings=sl,
                         confidence=max(s.confidence for s in sl), test_only=all("test" in s.context for s in sl)))
    return out
