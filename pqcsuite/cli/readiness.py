"""Readiness assessment: endpoint scans and probes, compliance evidence, and repository scans."""
import sys
from pathlib import Path

from .common import show, tls_client_args


def cmd_probe(a):
    from ..readiness.scan import GRADES, probe
    r = probe(a.target, a.server_name, a.timeout)
    r["verdict"] = f"{r['grade']}: {GRADES[r['grade']]}"
    show(r, a.json)
    return 0 if r["grade"] in "AB" else 2


def cmd_scan(a):
    from ..readiness import scan
    targets = scan.load_targets(a.targets)
    if not targets:
        raise ValueError("no targets: give host, host:port, ssh://host, or a .txt file with one per line")
    results = scan.scan(targets, a.workers, a.timeout)
    if a.html:
        Path(a.html).write_text(scan.report_html(results), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(scan.to_json(results), encoding="utf-8")
    for r in sorted(results, key=lambda r: (r["grade"], r["target"])):
        cert = r["certificate"] or {}
        print(f"{r['grade']}  {r['target']:32} {r['negotiated'] or r['error'] or '':24} {cert.get('key', ''):14} {cert.get('expires', '')}")
        if r.get("legacy"):
            print(f"   {'':32} also accepts {' and '.join(r['legacy']).replace('TLSv', 'TLS ')}: switch them off")
        if r.get("trusted") is False:
            print(f"   {'':32} certificate not trusted here ({cert.get('issuer', '?')}): a private CA, or a TLS-inspecting proxy "
                  "in the path, in which case these results describe the proxy; scan from outside that network")
    s = scan.summary(results)
    print(f"\n{s['pq_key_exchange']}/{s['endpoints']} offer post-quantum key exchange; {s['pq_certificates']} use ML-DSA certificates")
    print("".join(f"\n  {g}  {scan.GRADES[g]}" for g in scan.GRADES if s["grades"][g]))
    if s["grades"]["C"] or s["grades"]["B"]:
        print("\nNext: put the post-quantum edge in front of each C (pqcsuite tls edge --help; policy transition keeps browsers working),\n"
              "then scan again. For a report to share: add --html readiness.html")
    return 0 if s["pq_key_exchange"] == s["endpoints"] else 2


def cmd_report(a):
    from ..readiness import compliance
    from ..readiness import scan
    from ..console import App, Settings
    if not (a.ca or a.targets or a.vici or a.backups or a.wolfpack):
        raise ValueError("nothing to report on: pass --ca, --targets, --vici, --backups or --wolfpack")
    app = App(Settings(ca=a.ca or "", vpn=a.vici, backups=a.backups))
    rows = []
    if a.ca:
        rows += compliance.certificates(app.ca().records())
    targets = scan.load_targets(a.targets)
    if a.targets and not targets:
        raise ValueError("no targets in --targets: give host, host:port, ssh://host, or a .txt file with one per line")
    if targets:
        rows += compliance.endpoints(scan.scan(targets, timeout=a.timeout))
    rows += compliance.tunnels(app.tunnels()) + compliance.backups(app.backups())
    for scan_out in a.wolfpack:
        rows += compliance.code(scan_out)
    rep = compliance.report(rows)
    if a.html:
        Path(a.html).write_text(compliance.to_html(rep), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(compliance.to_json(rep), encoding="utf-8")
    s = rep["status"]
    print(f"{rep['assets']} assets: {s['action']} need action, {s['plan']} quantum-vulnerable to plan, {s['transition']} with classical fallback, "
          f"{s['ready']} quantum-safe" + (f", {s['note']} not used for security" if s['note'] else "") + f"; {rep['cnsa2_compliant']} {'meets' if rep['cnsa2_compliant'] == 1 else 'meet'} CNSA 2.0")
    return 0 if not s["action"] else 2


def cmd_project_scan(a):
    import webbrowser
    from ..project import scan
    result = scan(a.path, a.out, a.history, lambda stage: print(stage, file=sys.stderr))
    for note in result["notes"]:
        print(f"Warning: {note}", file=sys.stderr)
    summary, order = result["summary"], ("critical", "high", "medium", "low", "ok")
    n = summary["crypto_assets"]
    counts = ", ".join(f"{summary['priorities'][t]} {t}" for t in order if summary["priorities"].get(t))
    print(f"{result['project']}: {n} cryptographic asset{'' if n == 1 else 's'}{f' ({counts})' if counts else ''}")
    first = sorted((x for x in result["assets"] if x["tier"] in ("critical", "high") and not x["test_only"]), key=lambda x: order.index(x["tier"]))
    if first:
        print("Change first:")
        for x in first[:5]:
            where = f"{x['locations'][0][0]}:{x['locations'][0][1]}" if x["locations"] else ""
            print(f"  {x['tier']:8} {x['name']:16} {where:28} -> {x['action']}")
        tests = sum(x["tier"] in ("critical", "high") and x["test_only"] for x in result["assets"])
        more = ([f"{len(first) - 5} more"] if len(first) > 5 else []) + ([f"{tests} in test code"] if tests else [])
        if more:
            print(f"  ({' and '.join(more)}: see the report)")
    elif n:
        print("Nothing needs changing first; the report lists what to plan for.")
    print(f"Report: {Path(a.out) / 'report.html'} (open it in a browser); assessment.json holds the evidence")
    if a.open:
        webbrowser.open((Path(a.out) / "report.html").resolve().as_uri())
    return 0

def add(sub):
    r = sub.add_parser("readiness", help="Readiness assessment: TLS and SSH scans, CNSA 2.0, NIST IR 8547 evidence").add_subparsers(dest="readiness_cmd", required=True)
    p = r.add_parser("scan", help="grade many TLS and SSH endpoints")
    p.set_defaults(func=cmd_scan)
    p.add_argument("targets", nargs="+", help="host (port 443), host:port, ssh://host (port 22), or .txt files with one per line")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument("--json", help="write JSON results")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--timeout", type=float, default=8.0)
    p = r.add_parser("probe", help="which post-quantum groups does one server accept?")
    p.set_defaults(func=cmd_probe)
    tls_client_args(p)
    p = r.add_parser("report", help="compliance evidence: NIST IR 8547 and CNSA 2.0 status of every asset")
    p.set_defaults(func=cmd_report)
    p.add_argument("--ca", help="CA folder (certificates)")
    p.add_argument("--targets", nargs="*", default=[], help="host, host:port, ssh://host or .txt files to scan")
    p.add_argument("--vici", action="append", default=[])
    p.add_argument("--backups", action="append", default=[])
    p.add_argument("--wolfpack", action="append", default=[], metavar="FOLDER",
                   help="a Wolf Pack output folder (or its cbom.json): cryptography in code, with where it is used (repeatable)")
    p.add_argument("--html")
    p.add_argument("--json")
    p.add_argument("--timeout", type=float, default=8.0)

    p = sub.add_parser("scan", help="scan a local project: code relationships, cryptographic inventory and migration priorities")
    p.set_defaults(func=cmd_project_scan)
    p.add_argument("path", nargs="?", default=".", help="project folder (default: current folder)")
    p.add_argument("-o", "--out", default="pqcsuite-out", help="private local reports folder")
    p.add_argument("--open", action="store_true", help="open the completed offline report")
    p.add_argument("--history", help="keep the last 100 scan summaries in this local JSON file")
