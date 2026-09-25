import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import den, alpha
from .elders import CATALOG
from .scouts import source, config, artifacts, deps, tls, binary, iter_files, rel, read
from .scouts.lexer import LANGS


@dataclass
class Result:
    project: str
    sightings: list
    assets: list
    artifacts: list
    libraries: list
    alerts: list
    readiness: dict
    stats: dict
    notes: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    baseline: str = ""


def follow_trails(root, arts, sightings, include_vendor=False):
    """Alpha's hunt: find where keys and certificates are referenced, so deployed material is weighted as deployed."""
    local = [a for a in arts if "://" not in a.file]
    if not local or not Path(root).is_dir():
        return 0
    names = {Path(a.file).name: a for a in local}
    rx = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])")
    found = 0
    for p in iter_files(root, include_vendor):
        if p.suffix.lower() not in LANGS and not config.is_config(p):
            continue
        text = read(p)
        if not text:
            continue
        r = rel(root, p)
        for m in rx.finditer(text):
            a = names[m.group(1)]
            if r == a.file:
                continue
            line = text.count("\n", 0, m.start()) + 1
            a.details.setdefault("referenced_by", []).append(f"{r}:{line}")
            found += 1
            if config.is_config(p):
                for s in sightings:
                    if s.file == a.file:
                        s.context.add("deployed")
    return found


def load_baseline(path):
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    seen = set()
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        for o in (c.get("evidence") or {}).get("occurrences", []):
            seen.add((c.get("name"), o.get("location", "").split("!")[0]))
    return seen


def run(root, project, tls_targets=(), horizon=None, threshold=0.6, raw=False, second_look=True, include_vendor=False,
        ssh_targets=(), baseline=None):
    t0 = time.time()
    horizon = horizon or alpha.Horizon()
    src, n_code = source.scan(root, include_vendor)
    cfg, n_cfg = config.scan(root, include_vendor)
    arts, art_s, n_art = artifacts.scan(root, include_vendor)
    bin_s, bin_libs, n_bin = binary.scan(root, include_vendor)
    libs = deps.scan(root, include_vendor) + bin_libs
    live, notes, endpoints = [], [], []
    for t in tls_targets:
        s, a, n, ep = tls.probe(t)
        live += s
        arts += a
        notes += n
        endpoints.append(ep)
    for t in ssh_targets:
        s, a, n, ep = tls.probe_ssh(t)
        live += s
        notes += n
        endpoints.append(ep)
    sightings = src + cfg + art_s + bin_s + live
    raw_count = len(sightings)
    lines = den.Lines(root)
    trails = follow_trails(root, arts, sightings, include_vendor)
    if raw:
        sightings = [s for s in sightings if s.algo in CATALOG]
        for s in sightings:
            s.verdict, s.confidence, s.reason = "accepted", 1.0, "raw mode (den disabled)"
        promoted = 0
    else:
        sightings = den.verify(sightings, threshold, lines)
        promoted = den.second_look(sightings, lines, threshold) if second_look else 0
    assets = alpha.lead(den.assets(sightings), horizon)
    if baseline:
        seen = load_baseline(baseline)
        for a in assets:
            a.new_files = sorted({s.file.split("!")[0] for s in a.sightings if (a.variant, s.file.split("!")[0]) not in seen})
    al = alpha.alerts(arts, libs, sightings)
    stats = {"files_code": n_code, "files_config": n_cfg, "files_artifacts": n_art, "files_binary": n_bin, "libraries": len(libs),
             "endpoints": len(endpoints), "raw_sightings": raw_count,
             "accepted": sum(s.verdict == "accepted" for s in sightings), "quarantined": sum(s.verdict == "quarantined" for s in sightings),
             "rejected": sum(s.verdict == "rejected" for s in sightings), "suppressed": sum(s.verdict == "suppressed" for s in sightings),
             "promoted_on_second_look": promoted, "trails_followed": trails,
             "seconds": round(time.time() - t0, 2), "horizon": vars(horizon) | {"years_to_crqc": horizon.z}}
    return Result(project, sightings, assets, arts, libs, al, alpha.readiness(assets), stats, notes, endpoints, str(baseline or ""))
