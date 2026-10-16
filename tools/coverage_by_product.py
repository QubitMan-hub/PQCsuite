"""Baseline line coverage per destination product, over the current files that map to it (tools/coverage_map.toml)."""
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_map(path):
    data = tomllib.loads(Path(path).read_text())
    out = {}
    for dest, table in data.items():
        entries = table.items() if dest == "deleted" else ((f, "") for f in table["files"])
        for f, reason in entries:
            if f in out:
                raise ValueError(f"{f} is mapped twice")
            out[f] = (dest, reason)
    return out


def aggregate(stats, mapping):
    totals = {}
    for f, (statements, missed) in stats.items():
        dest = mapping[f][0]
        if dest != "deleted":
            s, m = totals.get(dest, (0, 0))
            totals[dest] = (s + statements, m + missed)
    return {d: round(100 * (s - m) / s, 1) for d, (s, m) in sorted(totals.items()) if s}


def main(data_file=".coverage"):
    import coverage
    mapping = load_map(ROOT / "tools" / "coverage_map.toml")
    cov = coverage.Coverage(data_file=str(ROOT / data_file))
    cov.load()
    stats = {}
    for f in mapping:
        if f.endswith(".py"):
            _, statements, _, missing, _ = cov.analysis2(str(ROOT / f))
            stats[f] = (len(statements), len(missing))
    for dest, pct in aggregate(stats, mapping).items():
        print(f"{dest:<10} {pct:5.1f}%")


if __name__ == "__main__":
    main(*sys.argv[1:])
