import argparse
import json
import shutil
import sys
import tempfile
import tomllib
import warnings
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from . import __version__, pack, cbom, report, image, inventory, compliance
from .alpha import Horizon, TIERS
from .pack import ROLES
from .scouts import Scope

SETTINGS = {"exclude": list, "include_vendor": bool, "tls": list, "ssh": list, "shelf_life": (int, float), "migration": (int, float),
            "crqc_year": int, "threshold": (int, float), "fail_on": str, "name": str, "policy": dict}


def main(argv=None):
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    ap = argparse.ArgumentParser(prog="wolfpack", description="Cryptographic inventory (CycloneDX 1.6 CBOM) and quantum migration planner")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", aliases=["hunt"], help="send the pack over a repository and/or live TLS and SSH endpoints")
    s.add_argument("path", nargs="?", default=None, help="folder to scan, or a container image saved with `docker save` or as an OCI archive (default: current folder, or none if only --tls/--ssh are given)")
    s.add_argument("--tls", action="append", default=[], metavar="HOST:PORT", help="probe a live TLS endpoint, including which key-exchange groups it accepts (repeatable)")
    s.add_argument("--ssh", action="append", default=[], metavar="HOST[:PORT]", help="read a live SSH server's algorithm lists (repeatable)")
    s.add_argument("--pcap", action="append", default=[], metavar="FILE",
                   help="read TLS and SSH handshakes from a packet capture (.pcap or .pcapng): what clients and servers actually negotiated (repeatable)")
    s.add_argument("--changed-since", metavar="GIT_REF", help="scan only files changed since this git ref (and uncommitted ones): fast CI checks on a pull request")
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
    s.add_argument("--policy", action="append", default=[], choices=compliance.PROFILES, metavar="PROFILE",
                   help=f"check against a published transition standard (repeatable): {', '.join(compliance.PROFILES)}; own rules go in [policy] in .wolfpack.toml")
    s.add_argument("--as-of", type=int, metavar="YEAR", help="judge policy deadlines as of this year (default: this year)")
    s.add_argument("--fail-on-policy", action="store_true", help="exit 2 if any policy rule is already broken (deadline passed or none)")
    s.add_argument("-q", "--quiet", action="store_true")
    m = sub.add_parser("merge", help="merge the CBOMs of many systems into one organisation inventory and dashboard")
    m.add_argument("cboms", nargs="+", metavar="CBOM", help="cbom.json files, or folders searched for them (other tools' CBOMs work too)")
    m.add_argument("--name", default="Organisation", help="organisation name for the inventory")
    m.add_argument("-o", "--out", default="wolfpack-inventory")
    m.add_argument("--fail-on", choices=TIERS[:-1], help="exit 2 if any system has an asset at this tier or worse")
    m.add_argument("--history", metavar="FILE", help="JSON-lines file of earlier runs: this run is added and the dashboard charts readiness over time")
    m.add_argument("-q", "--quiet", action="store_true")
    b = sub.add_parser("bench", help="score the full pack and each ablation against a labelled corpus")
    b.add_argument("corpus")
    b.add_argument("--truth", default=None)
    b.add_argument("--detail", action="store_true", help="list the false positives and negatives of every configuration")
    b.add_argument("--json", metavar="FILE", help="also write the table as JSON")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        raise SystemExit(1 if e.code == 2 else e.code)

    if a.cmd == "merge":
        return merge(a)
    if a.cmd == "bench":
        from .bench import main as bench
        return bench(a.corpus, a.truth, a.detail, a.json)

    cfg = settings(a.config, None if a.path is None and (a.tls or a.ssh or a.pcap) else Path(a.path or "."))
    a.exclude = cfg.get("exclude", []) + a.exclude
    a.tls = cfg.get("tls", []) + a.tls
    a.ssh = cfg.get("ssh", []) + a.ssh
    a.include_vendor = a.include_vendor or cfg.get("include_vendor", False)
    for k, default in (("shelf_life", 10), ("migration", 5), ("crqc_year", 2035), ("threshold", 0.6), ("fail_on", None), ("name", None)):
        if getattr(a, k) is None:
            setattr(a, k, cfg.get(k, default))
    policy = dict(cfg.get("policy", {}))
    problems = compliance.check(policy)
    if problems:
        sys.exit("wolfpack: " + "; ".join(problems))
    policy["profiles"] = list(dict.fromkeys(policy.get("profiles", []) + a.policy))
    if a.as_of:
        policy["as_of"] = a.as_of
    a.fail_on_policy = a.fail_on_policy or policy.get("fail", False)
    if a.fail_on is not None and a.fail_on not in TIERS[:-1]:
        sys.exit(f"wolfpack: fail_on must be one of {', '.join(TIERS[:-1])}")
    targets_only = a.path is None and (a.tls or a.ssh or a.pcap)
    root = Path(tempfile.mkdtemp()) if targets_only else Path(a.path or ".").resolve()
    if not root.exists():
        sys.exit(f"wolfpack: {a.path} does not exist")
    name = a.name or ((a.tls + a.ssh + [Path(p).name for p in a.pcap])[0] if targets_only else root.name)
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
    only = changed_files(root, a.changed_since) if a.changed_since else None
    h = Horizon(a.shelf_life, a.migration, a.crqc_year)
    unpacked, notes = None, []
    if image.is_image(root):
        unpacked = Path(tempfile.mkdtemp(prefix="wolfpack-image-"))
        notes = image.unpack(root, unpacked)
        name = a.name or root.name.split(".")[0]
    try:
        r = pack.run(unpacked or root, name, a.tls, h, a.threshold, pack.Roles.without(*a.without), Scope(a.include_vendor, tuple(a.exclude), only), a.ssh, a.baseline, a.pcap)
    finally:
        if unpacked:
            shutil.rmtree(unpacked, ignore_errors=True)
    r.notes[:0] = notes
    if only is not None:
        r.notes.insert(0, f"incremental scan: {len(only)} file(s) changed since {a.changed_since}; the rest of the repository was not read")
    if any(policy.get(k) for k in ("profiles", "forbid", "min_bits", "require_hybrid")):
        r.compliance = compliance.evaluate(r.assets, r.endpoints, policy)
    try:
        _write(out, name, r)
    except OSError as e:
        sys.exit(f"wolfpack: cannot write to {out}: {e}")
    if not a.quiet:
        print(report.terminal(r))
        print(f"\nwrote {out / 'cbom.json'}, {out / 'report.html'}, {out / 'wolfpack.sarif'}, {out / 'findings.json'}")
    if a.fail_on_policy and r.compliance and not r.compliance["passed"]:
        if not a.quiet:
            print(f"\nfailing: {r.compliance['overdue']} policy rule(s) already broken")
        sys.exit(2)
    if a.fail_on:
        bad = TIERS[:TIERS.index(a.fail_on) + 1]
        hits = [x for x in r.assets if x.tier in bad and (x.new_files or not a.baseline)]
        if hits:
            if not a.quiet:
                print(f"\nfailing: {len(hits)} asset(s) at {a.fail_on} or worse" + (" introduced since the baseline" if a.baseline else ""))
            sys.exit(2)
    return 0


def changed_files(root, ref):
    """Paths changed since `ref` plus uncommitted and untracked ones, relative to `root`, from git."""
    import subprocess
    run = lambda *args: subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.splitlines()
    try:
        top = Path(run("rev-parse", "--show-toplevel")[0])
        names = run("diff", "--name-only", ref) + run("ls-files", "--others", "--exclude-standard", "--full-name")
    except (OSError, subprocess.CalledProcessError, IndexError) as err:
        sys.exit(f"wolfpack: --changed-since needs a git repository and a valid ref ({err})")
    out = set()
    for n in names:
        try:
            out.add((top / n).resolve().relative_to(Path(root).resolve()).as_posix())
        except ValueError:
            continue
    return frozenset(out)


def merge(a):
    files = inventory.cbom_files(a.cboms)
    if not files:
        sys.exit("wolfpack: no cbom.json found in " + ", ".join(a.cboms))
    try:
        systems = inventory.run(files, a.name, a.out, a.history)
    except (OSError, ValueError) as err:
        sys.exit(f"wolfpack: cannot merge: {err}")
    if not a.quiet:
        print(inventory.terminal(a.name, systems))
        print(f"\nwrote {Path(a.out) / 'inventory.html'}, {Path(a.out) / 'inventory.json'}, {Path(a.out) / 'cbom.json'}")
    if a.fail_on:
        bad = TIERS[:TIERS.index(a.fail_on) + 1]
        if any(s["readiness"]["worst"] in bad for s in systems):
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
    (out / "findings.json").write_text(json.dumps(cbom.audit(r.sightings, r.notes) | {"stats": r.stats, "readiness": r.readiness, "compliance": r.compliance}, indent=2, default=str), encoding="utf-8")
    (out / "report.html").write_text(report.html(r), encoding="utf-8")
