"""The hunt, start to finish: scouts range wide, the den verifies, the alpha takes a second look and leads."""
import json
import time
from dataclasses import dataclass, field, fields
from pathlib import Path

from . import den, alpha
from .scouts import source, config, artifacts, deps, tls, binary, implementations, carried_hashes

SCOUTS = ("source", "implementations", "config", "artifacts", "binary")


@dataclass(frozen=True)
class Roles:
    """Which members of the pack take part. Switching one off is an ablation; docs/PACK.md says what each one does."""
    source: bool = True
    implementations: bool = True
    config: bool = True
    artifacts: bool = True
    binary: bool = True
    propagation: bool = True
    cross_file: bool = True
    den: bool = True
    corroboration: bool = True
    flow: bool = True
    registries: bool = True
    siblings: bool = True
    recognition: bool = True
    trails: bool = True

    @classmethod
    def without(cls, *names):
        off = set()
        for n in names:
            n = n.replace("-", "_")
            off |= set(alpha.LOOKS) if n == "second_look" else {n}
        unknown = off - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"unknown pack role: {', '.join(sorted(unknown))}")
        return cls(**dict.fromkeys(off, False))

    @property
    def off(self):
        return [f.name.replace("_", "-") for f in fields(self) if not getattr(self, f.name)]


ROLES = [f.name.replace("_", "-") for f in fields(Roles)] + ["second-look"]


@dataclass
class Hunt:
    sightings: list
    artifacts: list
    libraries: list
    files: dict
    notes: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)


def hunt(root, roles=Roles(), include_vendor=False, tls_targets=(), ssh_targets=()):
    """The scouts go out. Each reports everything it saw; nothing is filtered until the den."""
    h = Hunt([], [], [], dict.fromkeys(SCOUTS, 0))
    if roles.source:
        s, h.files["source"] = source.scan(root, include_vendor, roles.propagation, roles.cross_file)
        h.sightings += s
    if roles.implementations:
        s, h.files["implementations"] = implementations.scan(root, include_vendor)
        h.sightings += s
    if roles.config:
        s, h.files["config"] = config.scan(root, include_vendor)
        h.sightings += s
    if roles.artifacts:
        h.artifacts, s, h.files["artifacts"] = artifacts.scan(root, include_vendor)
        h.sightings += s
    if roles.binary:
        s, h.libraries, h.files["binary"] = binary.scan(root, include_vendor)
        h.sightings += s
    h.libraries = deps.scan(root, include_vendor) + h.libraries
    for t in tls_targets:
        s, a, n, ep = tls.probe(t)
        h.sightings += s
        h.artifacts += a
        h.notes += n
        h.endpoints.append(ep)
    for t in ssh_targets:
        s, _, n, ep = tls.probe_ssh(t)
        h.sightings += s
        h.notes += n
        h.endpoints.append(ep)
    h.sightings += carried_hashes(h.sightings)
    return h


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


def load_baseline(path):
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    seen = set()
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        for o in (c.get("evidence") or {}).get("occurrences", []):
            seen.add((c.get("name"), o.get("location", "").split("!")[0]))
    return seen


def run(root, project, tls_targets=(), horizon=None, threshold=0.6, roles=Roles(), include_vendor=False, ssh_targets=(), baseline=None):
    t0 = time.time()
    horizon = horizon or alpha.Horizon()
    h = hunt(root, roles, include_vendor, tls_targets, ssh_targets)
    lines = den.Lines(root)
    trails = alpha.follow_trails(root, h.artifacts, h.sightings, include_vendor) if roles.trails else 0
    if roles.den:
        sightings = den.verify(h.sightings, threshold, lines, roles.corroboration)
        looks = alpha.second_look(sightings, lines, threshold, [k for k in alpha.LOOKS if getattr(roles, k)], roles.recognition)
        held = alpha.recognise(sightings, lines) if roles.recognition else 0
    else:
        sightings, looks, held = den.admit_all(h.sightings), dict.fromkeys(alpha.LOOKS, 0), 0
    assets = alpha.lead(den.assets(sightings), horizon)
    if baseline:
        seen = load_baseline(baseline)
        for a in assets:
            a.new_files = sorted({s.file.split("!")[0] for s in a.sightings if (a.variant, s.file.split("!")[0]) not in seen})
    al = alpha.alerts(h.artifacts, h.libraries, sightings)
    stats = {"files_code": h.files["source"], "files_config": h.files["config"], "files_artifacts": h.files["artifacts"], "files_binary": h.files["binary"],
             "libraries": len(h.libraries), "endpoints": len(h.endpoints), "raw_sightings": len(h.sightings),
             "accepted": sum(s.verdict == "accepted" for s in sightings), "quarantined": sum(s.verdict == "quarantined" for s in sightings),
             "rejected": sum(s.verdict == "rejected" for s in sightings), "suppressed": sum(s.verdict == "suppressed" for s in sightings),
             "promoted_on_second_look": sum(looks.values()), "second_look": looks, "held_as_formats": held, "trails_followed": trails, "roles_off": roles.off,
             "seconds": round(time.time() - t0, 2), "horizon": vars(horizon) | {"years_to_crqc": horizon.z}}
    return Result(project, sightings, assets, h.artifacts, h.libraries, al, alpha.readiness(assets), stats, h.notes, h.endpoints, str(baseline or ""))
