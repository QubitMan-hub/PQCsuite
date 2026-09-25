import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__, pack, cbom, report
from .alpha import Horizon, TIERS


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wolfpack", description="Cryptographic inventory (CycloneDX 1.6 CBOM) and quantum migration planner")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repository and/or live TLS endpoints")
    s.add_argument("path", nargs="?", default=None, help="folder to scan (default: current folder, or none if only --tls/--ssh are given)")
    s.add_argument("--tls", action="append", default=[], metavar="HOST:PORT", help="probe a live TLS endpoint, including which key-exchange groups it accepts (repeatable)")
    s.add_argument("--ssh", action="append", default=[], metavar="HOST[:PORT]", help="read a live SSH server's algorithm lists (repeatable)")
    s.add_argument("--baseline", metavar="CBOM", help="previous cbom.json; report what is new and gate CI only on new findings")
    s.add_argument("-o", "--out", default="wolfpack-out")
    s.add_argument("--name", help="project name for the CBOM")
    s.add_argument("--shelf-life", type=float, default=10, help="years the protected data must stay secret (Mosca X)")
    s.add_argument("--migration", type=float, default=5, help="years your migration will take (Mosca Y)")
    s.add_argument("--crqc-year", type=int, default=2035, help="assumed year a cryptographically relevant quantum computer exists")
    s.add_argument("--threshold", type=float, default=0.6)
    s.add_argument("--raw", action="store_true", help="disable the den (ablation: every scout sighting is trusted)")
    s.add_argument("--no-second-look", action="store_true", help="disable the alpha's re-inspection pass (ablation)")
    s.add_argument("--include-vendor", action="store_true", help="also scan vendor/, node_modules/ and similar")
    s.add_argument("--fail-on", choices=TIERS[:-1], help="exit 2 if any asset is at this tier or worse (for CI)")
    s.add_argument("-q", "--quiet", action="store_true")
    b = sub.add_parser("bench", help="score the scanner against a labelled corpus")
    b.add_argument("corpus")
    b.add_argument("--truth", default=None)
    a = ap.parse_args(argv)

    if a.cmd == "bench":
        from .bench import main as bench
        return bench(a.corpus, a.truth)

    targets_only = a.path is None and (a.tls or a.ssh)
    root = Path(tempfile.mkdtemp()) if targets_only else Path(a.path or ".").resolve()
    if not root.exists():
        sys.exit(f"wolfpack: {a.path} does not exist")
    name = a.name or ((a.tls + a.ssh)[0] if targets_only else root.name)
    h = Horizon(a.shelf_life, a.migration, a.crqc_year)
    r = pack.run(root, name, a.tls, h, a.threshold, a.raw, not a.no_second_look, a.include_vendor, a.ssh, a.baseline)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cbom.json").write_text(json.dumps(cbom.build(name, r.assets, r.artifacts, r.libraries, r.endpoints), indent=2), encoding="utf-8")
    (out / "wolfpack.sarif").write_text(json.dumps(cbom.sarif(r.assets, r.alerts), indent=2), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(cbom.audit(r.sightings, r.notes) | {"stats": r.stats, "readiness": r.readiness}, indent=2, default=str), encoding="utf-8")
    (out / "report.html").write_text(report.html(r), encoding="utf-8")
    if not a.quiet:
        print(report.terminal(r))
        print(f"\nwrote {out / 'cbom.json'}, {out / 'report.html'}, {out / 'wolfpack.sarif'}, {out / 'findings.json'}")
    if a.fail_on:
        bad = TIERS[:TIERS.index(a.fail_on) + 1]
        hits = [x for x in r.assets if x.tier in bad and (x.new_files or not a.baseline)]
        if hits:
            if not a.quiet:
                print(f"\nfailing: {len(hits)} asset(s) at {a.fail_on} or worse" + (" introduced since the baseline" if a.baseline else ""))
            sys.exit(2)
    return 0
