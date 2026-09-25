import re
from collections import defaultdict
from pathlib import Path

from .elders import CATALOG, variant
from .model import Asset

BASE = {"live": 1.0, "binary": 0.8, "artifact": 0.95, "config": 0.9, "call": 0.9, "constant": 0.85, "identifier": 0.65, "import": 0.45, "string": 0.35}
RANK = {k: i for i, k in enumerate(["string", "import", "identifier", "binary", "constant", "call", "config", "artifact", "live"])}
KIN = {"ECC": "EC", "ECDSA": "EC", "ECDH": "EC"}
HARD = {"comment": "appears only inside a comment", "doc": "appears only in a docstring", "prose": "mentioned in human-readable text, not used"}
KEY_PARAMS = ("key_size", "curve", "mode", "hash", "padding")
NOISE = re.compile(r"\b(print\w*|log\w*|debug|info|warn\w*|error|trace|format|printf|append|equals\w*|contains|includes|startsWith|endsWith|assert\w*|expect)\s*\(", re.I)


def _kin(a):
    return KIN.get(a, a)


def dedupe(sightings):
    best = {}
    for s in sightings:
        k = (s.file, s.line, s.algo, "comment" in s.context)
        cur = best.get(k)
        if cur is None or RANK[s.evidence] > RANK[cur.evidence]:
            if cur:
                for p, v in cur.params.items():
                    s.params.setdefault(p, v)
            best[k] = s
        else:
            for p, v in s.params.items():
                cur.params.setdefault(p, v)
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


def verify(sightings, threshold=0.6, lines=None):
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
            others = [o for o in group if o is not s and _kin(o.algo) == _kin(s.algo) and o.evidence != s.evidence]
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


DENY_NAME = re.compile(r"disabl|deny|denied|block|forbid|reject|insecure|weak|deprecat|legacy_only|exclude|blacklist", re.I)


def siblings(sightings):
    """A literal like "RS256" yields RSA and SHA-256; if one half is accepted, so is the other."""
    ok = {(s.file, s.line, s.snippet) for s in sightings if s.verdict == "accepted" and s.evidence == "string"}
    n = 0
    for s in sightings:
        if s.verdict == "quarantined" and s.evidence == "string" and (s.file, s.line, s.snippet) in ok:
            s.verdict, s.confidence, s.reason = "accepted", 0.7, "same literal as an accepted sighting"
            n += 1
    return n


def list_name(ls, first):
    """Name of the variable a list is assigned to, read from the nearest code line at or above its first entry."""
    for k in range(first, max(0, first - 8), -1):
        if k > len(ls):
            continue
        line = ls[k - 1].split("#")[0].split("//")[0]
        m = re.search(r"([A-Za-z_][\w.]*)['\"]?\s*(?::[^=\n]{1,40})?(?::=|=|:)\s*[\[({]", line)
        if m:
            return m.group(1)
    return ""


def registries(sightings, lines, size=3, gap=2):
    """Three or more crypto literals packed into one list or table form an algorithm registry, unless it is a deny-list."""
    by_file = defaultdict(list)
    for s in sightings:
        if s.evidence == "string" and s.verdict in ("quarantined", "accepted") and s.line:
            by_file[s.file].append(s)
    n = 0
    for f, group in by_file.items():
        group.sort(key=lambda s: s.line)
        cluster = [group[0]]
        for s in group[1:] + [None]:
            if s is not None and s.line - cluster[-1].line <= gap:
                cluster.append(s)
                continue
            if len({c.line for c in cluster}) >= size:
                if not DENY_NAME.search(list_name(lines(f), cluster[0].line)):
                    for c in cluster:
                        if c.verdict == "quarantined":
                            c.verdict, c.confidence, c.reason = "accepted", 0.65, f"part of an algorithm list of {len(cluster)} entries (lines {cluster[0].line}-{cluster[-1].line})"
                            n += 1
            cluster = [s] if s is not None else []
    return n


def second_look(sightings, lines, threshold=0.6):
    """Re-inspects quarantined string literals: accept only if the literal visibly flows into a call."""
    promoted = 0
    for s in sightings:
        if s.verdict != "quarantined" or s.evidence != "string":
            continue
        ls = lines(s.file)
        if not (0 < s.line <= len(ls)):
            continue
        line = ls[s.line - 1]
        lits = re.findall(r"""(['"`])(.*?)\1""", line)
        hit = None
        for _, lit in lits:
            e = re.escape(lit)
            m = re.match(r"\s*(?:(?:const|let|var|final|static|private|public|protected|readonly|val)\s+)*(?:[\w<>\[\]]+\s+)?([A-Za-z_]\w*)\s*[:=]\s*['\"`]" + e, line)
            if m:
                var = re.escape(m.group(1))
                for k in range(s.line, min(len(ls), s.line + 40)):
                    if (re.search(r"\w\s*\([^)]*\b" + var + r"\b", ls[k]) and not NOISE.search(ls[k])) or re.search(r"\b\w+\s*=\s*" + var + r"\b\s*[,)]", ls[k]):
                        hit = f"constant {m.group(1)} flows into a call on line {k + 1}"
                        break
            elif re.search(r"\w\s*\([^)]*['\"`]" + e + r"['\"`]", line) and not NOISE.search(line) or re.search(
                    r"(alg\w*|cipher\w*|hash\w*|digest\w*|curve\w*|kex\w*|sig\w*|scheme\w*|transformation\w*|protocol\w*|padding\w*)['\"]?\s*(?::[^=\n]{1,40})?[:=]\s*[\[(]?\s*['\"`]" + e, line, re.I):
                hit = "literal is passed directly into a call or algorithm setting"
            if hit:
                break
        if hit:
            s.verdict, s.confidence, s.reason = "accepted", max(threshold, 0.7), f"second look: {hit}"
            promoted += 1
    return promoted + registries(sightings, lines) + siblings(sightings)


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
