import argparse
import json
import sys
import tempfile
import tomllib
import warnings
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from . import __version__, pack, cbom, report
from .alpha import Horizon, TIERS
from .pack import ROLES
from .scouts import Scope

SETTINGS = {"exclude": list, "include_vendor": bool, "tls": list, "ssh": list, "shelf_life": (int, float), "migration": (int, float),
            "crqc_year": int, "threshold": (int, float), "fail_on": str, "name": str}


def main(argv=None):
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    ap = argparse.ArgumentParser(prog="wolfpack", description="Cryptographic inventory (CycloneDX 1.6 CBOM) and quantum migration planner")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", aliases=["hunt"], help="send the pack over a repository and/or live TLS and SSH endpoints")
    s.add_argument("path", nargs="?", default=None, help="folder to scan (default: current folder, or none if only --tls/--ssh are given)")
    s.add_argument("--tls", action="append", default=[], metavar="HOST:PORT", help="probe a live TLS endpoint, including which key-exchange groups it accepts (repeatable)")
    s.add_argument("--ssh", action="append", default=[], metavar="HOST[:PORT]", help="read a live SSH server's algorithm lists (repeatable)")
    s.add_argument("--baseline", metavar="CBOM", help="previous cbom.json; report what is new and gate CI only on new findings")
    s.add_argument("-o", "--out", default="wolfpack-out")
    s.add_argument("--name", help="project name for the CBOM")
    s.add_argument("--config", metavar="FILE", help="settings file (default: .wolfpack.toml in the scanned folder, if present)")
    s.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="leave out matching files and folders: a name glob (generated, *.min.js) or a path glob from the root (docs/old/*); repeatable")
    s.add_argument("--shelf-life", type=float, help="years the protected data must stay secret (Mosca X, default 10)")
    s.add_argument("--migration", type=float, help="years your migration will take (Mosca Y, default 5)")
    s.add_argument("--crqc-year", type=int, help="assumed year a cryptographically relevant quantum computer exists (default 2035)")
    s.add_argument("--threshold", type=float, help="den confidence needed to accept a finding (default 0.6)")
    s.add_argument("--without", action="append", default=[], choices=ROLES, metavar="ROLE",
                   help=f"leave a member of the pack out (ablation, repeatable): {', '.join(ROLES)}")
    s.add_argument("--include-vendor", action="store_true", help="also scan vendor/, node_modules/ and similar")
    s.add_argument("--fail-on", choices=TIERS[:-1], help="exit 2 if any asset is at this tier or worse (for CI)")
    s.add_argument("-q", "--quiet", action="store_true")
    b = sub.add_parser("bench", help="score the full pack and each ablation against a labelled corpus")
    b.add_argument("corpus")
    b.add_argument("--truth", default=None)
    b.add_argument("--detail", action="store_true", help="list the false positives and negatives of every configuration")
    b.add_argument("--json", metavar="FILE", help="also write the table as JSON")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        raise SystemExit(1 if e.code == 2 else e.code)

    if a.cmd == "bench":
        from .bench import main as bench
        return bench(a.corpus, a.truth, a.detail, a.json)

    cfg = settings(a.config, None if a.path is None and (a.tls or a.ssh) else Path(a.path or "."))
    a.exclude = cfg.get("exclude", []) + a.exclude
    a.tls = cfg.get("tls", []) + a.tls
    a.ssh = cfg.get("ssh", []) + a.ssh
    a.include_vendor = a.include_vendor or cfg.get("include_vendor", False)
    for k, default in (("shelf_life", 10), ("migration", 5), ("crqc_year", 2035), ("threshold", 0.6), ("fail_on", None), ("name", None)):
        if getattr(a, k) is None:
            setattr(a, k, cfg.get(k, default))
    if a.fail_on is not None and a.fail_on not in TIERS[:-1]:
        sys.exit(f"wolfpack: fail_on must be one of {', '.join(TIERS[:-1])}")
    targets_only = a.path is None and (a.tls or a.ssh)
    root = Path(tempfile.mkdtemp()) if targets_only else Path(a.path or ".").resolve()
    if not root.exists():
        sys.exit(f"wolfpack: {a.path} does not exist")
    name = a.name or ((a.tls + a.ssh)[0] if targets_only else root.name)
    if a.baseline:
        try:
            pack.load_baseline(a.baseline)
        except (OSError, ValueError, AttributeError) as e:
            sys.exit(f"wolfpack: cannot read the baseline {a.baseline}: {e}")
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"wolfpack: cannot write to {out}: {e}")
    h = Horizon(a.shelf_life, a.migration, a.crqc_year)
    r = pack.run(root, name, a.tls, h, a.threshold, pack.Roles.without(*a.without), Scope(a.include_vendor, tuple(a.exclude)), a.ssh, a.baseline)
    try:
        _write(out, name, r)
    except OSError as e:
        sys.exit(f"wolfpack: cannot write to {out}: {e}")
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


def settings(path, root):
    """Settings from --config, or from .wolfpack.toml in the scanned folder. Keys are the long option names with underscores."""
    f = Path(path) if path else root / ".wolfpack.toml" if root and root.is_dir() else None
    if f is None or (not path and not f.exists()):
        return {}
    try:
        cfg = tomllib.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        sys.exit(f"wolfpack: cannot read {f}: {e}")
    for k, v in cfg.items():
        if k not in SETTINGS:
            sys.exit(f"wolfpack: {f}: unknown setting {k!r} (known: {', '.join(SETTINGS)})")
        if not isinstance(v, SETTINGS[k]) or (SETTINGS[k] is list and not all(isinstance(x, str) for x in v)):
            sys.exit(f"wolfpack: {f}: {k} has the wrong type")
    return cfg


def _write(out, name, r):
    (out / "cbom.json").write_text(json.dumps(cbom.build(name, r.assets, r.artifacts, r.libraries, r.endpoints), indent=2), encoding="utf-8")
    (out / "wolfpack.sarif").write_text(json.dumps(cbom.sarif(r.assets, r.alerts), indent=2), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(cbom.audit(r.sightings, r.notes) | {"stats": r.stats, "readiness": r.readiness}, indent=2, default=str), encoding="utf-8")
    (out / "report.html").write_text(report.html(r), encoding="utf-8")
