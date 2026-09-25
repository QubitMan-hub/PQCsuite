"""Held-out benchmark kit: fetch pinned repos, make blind label sheets, check them, measure labeller agreement, score the tools."""
import argparse
import csv
import json
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE.parent / "cbomkit"))

from wolfpack import pack, __version__
from wolfpack.bench import CONFIGS
from wolfpack.elders import CATALOG
from wolfpack.scouts import iter_files, rel, is_test, config, artifacts
from wolfpack.scouts.lexer import LANGS

REPOS = HERE / "repos"
LABELS = HERE / "labels"
FAMILIES = {a.family.upper(): a.family for a in CATALOG.values()}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "go.sum", "cargo.lock", "poetry.lock"}
COLUMNS = ["file", "used", "declared", "notes"]


def manifest():
    return json.loads((HERE / "repos.json").read_text(encoding="utf-8"))


def scope(root):
    """Files a labeller must look at: non-test source, config and key/certificate files. Binaries are out of scope."""
    out = []
    for p in iter_files(root):
        r = rel(root, p)
        if is_test(r) or p.name.lower() in LOCKFILES or r.startswith(".github/"):
            continue
        ext = p.suffix.lower()
        if ext in LANGS or ext in artifacts.EXT or config.is_config(p):
            out.append(r)
    return sorted(out)


def parse_cell(cell):
    """'RSA; SHA-256' -> ({'RSA', 'SHA-256'}, []) ; '-' -> (set(), []) ; '' -> None (not labelled yet)."""
    cell = (cell or "").strip()
    if not cell:
        return None
    if cell == "-":
        return set(), []
    fams, bad = set(), []
    for tok in (t.strip() for t in cell.split(";")):
        if not tok:
            continue
        if tok.upper().startswith("OTHER:") and len(tok) > 6:
            fams.add("OTHER:" + tok[6:].strip().upper())
        elif tok.upper() in FAMILIES:
            fams.add(FAMILIES[tok.upper()])
        else:
            bad.append(tok)
    return fams, bad


def read_sheet(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def load_labels(path):
    """Returns ({file: (used, declared)}, problems)."""
    labels, problems = {}, []
    for i, row in enumerate(read_sheet(path), 2):
        used, declared = parse_cell(row.get("used")), parse_cell(row.get("declared"))
        if used is None or declared is None:
            problems.append(f"{path.name}:{i} {row['file']}: 'used' and 'declared' must both be filled ('-' means none)")
            continue
        for tok in used[1] + declared[1]:
            problems.append(f"{path.name}:{i} {row['file']}: unknown family '{tok}' (use a name from the vocabulary or OTHER:<name>)")
        labels[row["file"]] = (used[0], declared[0] - used[0])
    return labels, problems


def gold(labels, policy):
    return {(f, fam) for f, (u, d) in labels.items() for fam in (u | d if policy == "inclusive" else u)}


def prf(found, truth):
    tp = len(found & truth)
    p = tp / len(found) if found else 1.0
    r = tp / len(truth) if truth else 1.0
    return tp, len(found), len(truth), p, r, (2 * p * r / (p + r) if p + r else 0.0)


def micro(rows):
    tp, nf, ng = (sum(r[k] for r in rows) for k in range(3))
    p, r = (tp / nf if nf else 1.0), (tp / ng if ng else 1.0)
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def bootstrap(rows, n=2000, seed=0):
    """95% interval for micro precision and recall, resampling repos."""
    rng, ps, rs = random.Random(seed), [], []
    for _ in range(n):
        p, r, _ = micro([rng.choice(rows) for _ in rows])
        ps.append(p)
        rs.append(r)
    ci = lambda xs: (sorted(xs)[int(0.025 * n)], sorted(xs)[int(0.975 * n) - 1])
    return ci(ps), ci(rs)


def wolfpack_pairs(root, files, roles=pack.Roles()):
    r = pack.run(root, root.name, roles=roles)
    return {(s.file, CATALOG[s.algo].family) for s in r.sightings if s.verdict == "accepted" and s.algo in CATALOG and s.file in files}


def cmd_fetch(a):
    REPOS.mkdir(exist_ok=True)
    for r in manifest():
        dest = REPOS / r["name"]
        if (dest / ".git").exists():
            print(f"{r['name']}: already fetched")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        git = lambda *args: subprocess.run(["git", *args], cwd=dest, check=True, capture_output=True)
        git("init", "-q")
        git("fetch", "-q", "--depth", "1", f"https://github.com/{r['repo']}", r["commit"])
        git("checkout", "-q", "FETCH_HEAD")
        print(f"{r['name']}: {r['repo']} @ {r['commit'][:10]}, {len(scope(dest))} files in scope")


def cmd_sheets(a):
    out = LABELS / a.labeller
    out.mkdir(parents=True, exist_ok=True)
    for r in manifest():
        root, sheet = REPOS / r["name"], out / f"{r['name']}.csv"
        if not root.exists():
            sys.exit(f"{r['name']} is not fetched; run: python eval/heldout/heldout.py fetch")
        if sheet.exists():
            print(f"{sheet}: exists, left untouched")
            continue
        with open(sheet, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(COLUMNS)
            for file in scope(root):
                w.writerow([file, "", "", ""])
        print(f"{sheet}: {len(scope(root))} files to label")


def cmd_check(a):
    total, done, problems = 0, 0, []
    for sheet in sorted((LABELS / a.labeller).glob("*.csv")):
        rows = read_sheet(sheet)
        labels, p = load_labels(sheet)
        missing = set(scope(REPOS / sheet.stem)) - {r["file"] for r in rows} if (REPOS / sheet.stem).exists() else set()
        problems += p + [f"{sheet.name}: in-scope file missing from the sheet: {m}" for m in sorted(missing)]
        total += len(rows)
        done += len(labels)
        print(f"{sheet.stem:<20} {len(labels):>4}/{len(rows):<4} labelled, {sum(bool(u or d) for u, d in labels.values())} files with crypto")
    print(f"\n{done}/{total} files labelled")
    for p in problems[:200]:
        print("  " + p)
    return 1 if problems else 0


def cmd_agree(a):
    print(f"{'repo':<20}{'policy':<11}{'A pairs':>8}{'B pairs':>8}{'both':>6}{'agreement':>11}")
    for sheet in sorted((LABELS / a.a).glob("*.csv")):
        other = LABELS / a.b / sheet.name
        if not other.exists():
            continue
        la, lb = load_labels(sheet)[0], load_labels(other)[0]
        common = set(la) & set(lb)
        for policy in ("strict", "inclusive"):
            ga = {x for x in gold(la, policy) if x[0] in common}
            gb = {x for x in gold(lb, policy) if x[0] in common}
            dice = 2 * len(ga & gb) / (len(ga) + len(gb)) if ga or gb else 1.0
            print(f"{sheet.stem:<20}{policy:<11}{len(ga):>8}{len(gb):>8}{len(ga & gb):>6}{dice:>11.3f}")
    return 0


def cmd_score(a):
    sheets = sorted((LABELS / a.labeller).glob("*.csv"))
    if not sheets:
        sys.exit(f"no sheets in {LABELS / a.labeller}")
    labelled, problems = {}, []
    for sheet in sheets:
        labels, p = load_labels(sheet)
        problems += p
        labelled[sheet.stem] = labels
    if problems and not a.partial:
        sys.exit("labels are incomplete or invalid; run `check` first (or pass --partial for a dry run):\n  " + "\n  ".join(problems[:20]))
    configs = CONFIGS if a.ablations else CONFIGS[:1]
    report = {"wolfpack": __version__, "labeller": a.labeller, "results": {}}
    for policy in ("strict", "inclusive"):
        print(f"\n== {policy} policy ({'used only' if policy == 'strict' else 'used + declared'})")
        for name, off in configs:
            rows = []
            for repo, labels in labelled.items():
                files = set(labels)
                found = wolfpack_pairs(REPOS / repo, files, pack.Roles.without(*off))
                rows.append(prf(found, gold(labels, policy)))
                if name == "full pack" and a.per_repo:
                    print(f"  {repo:<20} P {rows[-1][3]:.3f}  R {rows[-1][4]:.3f}  ({rows[-1][0]} tp, {rows[-1][1]} found, {rows[-1][2]} gold)")
            p, r, f1 = micro(rows)
            (pl, ph), (rl, rh) = bootstrap(rows)
            print(f"  {name:<26} P {p:.3f} [{pl:.2f}, {ph:.2f}]  R {r:.3f} [{rl:.2f}, {rh:.2f}]  F1 {f1:.3f}")
            report["results"][f"{policy}/{name.strip()}"] = {"precision": p, "recall": r, "f1": f1, "p95": [pl, ph], "r95": [rl, rh]}
        if a.cbomkit:
            from compare import CBOMKIT_LANGS, cbomkit_pairs
            rows_wp, rows_ck = [], []
            for repo, labels in labelled.items():
                cb = Path(a.cbomkit) / repo / "cbom.json"
                if not cb.exists():
                    continue
                files = {f for f in labels if Path(f).suffix.lower() in CBOMKIT_LANGS}
                truth = {x for x in gold(labels, policy) if x[0] in files}
                rows_wp.append(prf(wolfpack_pairs(REPOS / repo, files), truth))
                rows_ck.append(prf({x for x in cbomkit_pairs(cb, REPOS / repo, True) if x[0] in files}, truth))
            for name, rows in (("wolfpack, CBOMkit languages", rows_wp), ("cbomkit, CBOMkit languages", rows_ck)):
                if rows:
                    p, r, f1 = micro(rows)
                    print(f"  {name:<26} P {p:.3f}  R {r:.3f}  F1 {f1:.3f}  ({len(rows)} repos)")
                    report["results"][f"{policy}/{name}"] = {"precision": p, "recall": r, "f1": f1}
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch", help="clone every repo in repos.json at its pinned commit into eval/heldout/repos/")
    s = sub.add_parser("sheets", help="write a blank label sheet per repo (never overwrites)")
    s.add_argument("--labeller", required=True)
    c = sub.add_parser("check", help="validate a labeller's sheets")
    c.add_argument("--labeller", required=True)
    g = sub.add_parser("agree", help="agreement between two labellers on the repos both labelled")
    g.add_argument("a")
    g.add_argument("b")
    sc = sub.add_parser("score", help="score Wolf Pack (and optionally CBOMkit) against one labeller's finished sheets")
    sc.add_argument("--labeller", required=True)
    sc.add_argument("--ablations", action="store_true", help="also score every single-role ablation")
    sc.add_argument("--cbomkit", metavar="DIR", help="folder with <repo>/cbom.json from CBOMkit-action")
    sc.add_argument("--per-repo", action="store_true")
    sc.add_argument("--partial", action="store_true", help="score even if sheets are incomplete (never for reported results)")
    sc.add_argument("--json", metavar="FILE")
    a = ap.parse_args(argv)
    return {"fetch": cmd_fetch, "sheets": cmd_sheets, "check": cmd_check, "agree": cmd_agree, "score": cmd_score}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
