"""One local project scan: existing Wolf Pack discovery, call relationships, and migration evidence."""
import json
import time
from collections import Counter
from pathlib import Path

from .storage import write, locked


def scanner():
    try:
        from wolfpack import pack, report
        from wolfpack.crawler import CodeCrawler  # noqa: F401
    except ImportError:
        raise ValueError("Project scanning needs the current Wolf Pack. From the checkout run: pip install ./wolf-pack '.[scan]'") from None
    return pack, report


def scan(path, out=None, history=None, progress=None):
    notify = progress or (lambda stage: None)
    notify("Preparing project")
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError("Choose an existing project folder")
    pack, report = scanner()
    notify("Analyzing source and cryptography")
    from wolfpack.scouts import Scope
    excluded = []
    for destination in (out, history):
        if destination:
            try:
                excluded.append(Path(destination).resolve().relative_to(root).as_posix())
            except ValueError:
                pass
    result = pack.run(root, root.name, scope=Scope(exclude=tuple(excluded)))
    notify("Preparing migration results")
    # Unified results deliberately omit source snippets and literal values. No code is uploaded/executed.
    for sighting in result.sightings:
        sighting.snippet = ""
        sighting.params.pop("literal", None)
    assets = [{"name": a.variant, "algorithm": a.algo, "tier": a.tier, "why": a.why, "action": a.action,
               "confidence": a.confidence, "test_only": a.test_only, "declared": a.declared,
               "locations": sorted({(s.file, s.line) for s in a.sightings}), "impact": a.params.get("code_impact")}
              for a in result.assets]
    graph = result.relationships
    assessment = {"project": root.name, "finished": time.time(), "assets": assets, "notes": result.notes,
                  "summary": {"crypto_assets": len(assets), "priorities": dict(Counter(a["tier"] for a in assets)),
                              "python_files": graph.get("languages", {}).get("Python", 0), "languages": graph.get("languages", {}), "coverage_gaps": graph.get("skipped", {}),
                              "migration_candidates": sum(a["tier"] in {"critical", "high"} and not a["test_only"] and not a["declared"] for a in assets), "functions": sum(s["kind"] == "function" for s in graph["symbols"]),
                              "resolved_calls": sum(bool(c["target"]) for c in graph["calls"]), "calls": len(graph["calls"]),
                              "libraries": result.stats["libraries"], "seconds": result.stats["seconds"], "graph_limited": graph["limited"]},
                  "evidence_boundary": "Static source evidence is not runtime protection or proof of business ownership.",
                  "relationships": graph}
    if out:
        folder = Path(out)
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        report.write_results(folder, root.name, result)
    if history:
        try:
            append_history(history, assessment)
        except (OSError, ValueError):
            assessment["notes"].append("History could not be saved; check the configured history file. Scan evidence remains available.")
    if out:
        write(folder / "assessment.json", json.dumps(assessment, indent=2).encode(), secret=True)
    notify("Complete")
    return assessment


def read_history(path):
    f = Path(path)
    if not f.exists():
        return []
    with f.open("rb") as source:
        raw = source.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Scan history exceeds the 1 MB limit")
    rows = json.loads(raw)
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("project"), str)
                                        or type(row.get("finished")) not in {int, float} or not 0 <= row["finished"] <= 2**53 or not isinstance(row.get("summary"), dict) for row in rows):
        raise ValueError("Scan history must contain project/time/summary records")
    return [{k: row[k] for k in ("project", "finished", "summary")} for row in rows[-100:]]


def append_history(path, assessment):
    """Persist bounded summaries under the same shared lock used for atomic CA state updates."""
    f = Path(path).absolute()
    f.parent.mkdir(parents=True, exist_ok=True)
    with locked(f.parent, "." + f.name + ".lock"):
        rows = read_history(f)[-99:] + [{k: assessment[k] for k in ("project", "finished", "summary")}]
        write(f, json.dumps(rows, indent=2).encode(), secret=True)
