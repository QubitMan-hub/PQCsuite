"""One local project scan: existing Wolf Pack discovery, call relationships, and migration evidence."""
import json
import time
from collections import Counter
from pathlib import Path

from .pki import write


def scanner():
    try:
        from wolfpack import pack, cli
        from wolfpack.crawler import CodeCrawler  # noqa: F401
    except ImportError:
        raise ValueError("Project scanning needs the current Wolf Pack. From the checkout run: pip install ./wolf-pack '.[scan]'") from None
    return pack, cli


def scan(path, out=None, history=None, progress=None):
    notify = progress or (lambda stage: None)
    notify("Preparing project")
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError("Choose an existing project folder")
    pack, cli = scanner()
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
                              "python_files": graph["files_analyzed"], "functions": sum(s["kind"] == "function" for s in graph["symbols"]),
                              "resolved_calls": sum(bool(c["target"]) for c in graph["calls"]), "calls": len(graph["calls"]),
                              "libraries": result.stats["libraries"], "seconds": result.stats["seconds"], "graph_limited": graph["limited"]},
                  "evidence_boundary": "Static source evidence is not runtime protection or proof of business ownership.",
                  "relationships": graph}
    if out:
        folder = Path(out)
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        cli.write_results(folder, root.name, result)
        write(folder / "assessment.json", json.dumps(assessment, indent=2).encode(), secret=True)
    if history:
        append_history(history, assessment)
    notify("Complete")
    return assessment


def append_history(path, assessment):
    """Persist bounded summaries only: no source snippets or full graphs in the history."""
    f = Path(path)
    if f.exists() and f.stat().st_size > 1_000_000:
        raise ValueError("Scan history exceeds the 1 MB limit")
    rows = json.loads(f.read_text()) if f.exists() else []
    if not isinstance(rows, list):
        raise ValueError("Scan history must contain a JSON list")
    rows = rows[-99:] + [{k: assessment[k] for k in ("project", "finished", "summary")}]
    write(f, json.dumps(rows, indent=2).encode(), secret=True)
