"""The release gate. Two steps, both run by .github/workflows/release.yml:

    python scripts/release_readiness.py evidence evidence.json SBOM.json
        runs the suite and the benchmark on this machine and records the results
    python scripts/release_readiness.py report TAG SHA evidence.json RELEASE_READINESS.md [SBOM.json CBOM.json]
        waits for the commit's CI and CodeQL jobs (GitHub API: GH_TOKEN, GITHUB_REPOSITORY), writes the report and exits 1
        unless every required job passed; with this release's SBOM and CBOM, it also lists what changed since the last one

What is not validated yet is copied from docs/RELEASE-READINESS.md, so the report never implies more than was checked.
"""
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATES = {  # gate: [(what it shows, check run name or prefix, how many)]
    "Correct": [("Unit tests, Linux and Windows, Python 3.11 and 3.13", "ci/unit (", 4),
                ("Full suite with nginx, PostgreSQL, Redis, MQTT, SSH; clinic and bank demos", "ci/tls", 1),
                ("Website and console in Chromium, with accessibility checks", "ci/browser", 1), ("Lint", "ci/lint", 1)],
    "Secure": [("Known vulnerabilities in dependencies (pip-audit)", "ci/audit", 1),
               ("Container image: Trivy, fixable HIGH/CRITICAL", "ci/docker", 1),
               ("No new high-risk cryptography (Wolf Pack against docs/cbom.json)", "ci/cbom", 1),
               ("CodeQL: Python, JavaScript, workflows", "codeql/analyze (", 3)],
    "Operational": [("Kubernetes: Helm install in kind, post-quantum request through the edge", "ci/kubernetes", 1),
                    ("IPsec and WireGuard with real traffic in network namespaces; VPN demo", "ci/vpn", 1),
                    ("Cloud image: Packer template and provisioning on Debian 13", "ci/cloud-image", 1)],
}


def api(path):
    req = urllib.request.Request(f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/{path}",
                                 headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                                          **({"Authorization": f"Bearer {os.environ['GH_TOKEN']}"} if os.environ.get("GH_TOKEN") else {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def matches(name, check):
    return name.startswith(check) if check.endswith("(") else name == check


def runs(sha, wait_s=2700):
    """The latest check run per name, once every required one has finished (or the wait is over)."""
    deadline = time.monotonic() + wait_s
    while True:
        workflows = {r["id"]: r["name"] for r in api(f"actions/runs?head_sha={sha}&per_page=100")["workflow_runs"]}
        latest = {}
        for r in sorted(api(f"commits/{sha}/check-runs?per_page=100")["check_runs"], key=lambda r: r["started_at"] or ""):
            run = re.search(r"/actions/runs/(\d+)/", r["html_url"] or "")
            r["name"] = f"{workflows.get(int(run.group(1)), '?') if run else '?'}/{r['name']}"
            latest[r["name"]] = r
        ready = all(len(jobs := [r for n, r in latest.items() if matches(n, check)]) >= count and all(r["status"] == "completed" for r in jobs)
                    for checks in GATES.values() for _, check, count in checks)
        if ready or time.monotonic() > deadline:
            return latest
        time.sleep(30)


def previous(tag):
    """The suite release before `tag`, or None."""
    v = lambda t: tuple(map(int, t[1:].split(".")))
    older = [r for r in api("releases?per_page=50") if re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"]) and not r["draft"] and v(r["tag_name"]) < v(tag)]
    return max(older, key=lambda r: v(r["tag_name"]), default=None)


def asset(release, suffix):
    a = next((a for a in release["assets"] if a["name"].endswith(suffix)), None)
    if a:
        with urllib.request.urlopen(a["browser_download_url"], timeout=30) as r:
            return json.loads(r.read())


def since(tag, sbom, cbom):
    """What changed in the dependencies (SBOM) and in the cryptography found in the code (CBOM) since the previous release."""
    prev = previous(tag)
    if not prev:
        return "First release with a readiness record; nothing to compare with."
    lines = ["| | Since " + prev["tag_name"] + " |", "|---|---|"]
    old = asset(prev, "-sbom.json")
    if old:
        deps = lambda d: {c["name"]: c.get("version", "") for c in d.get("components", []) if c["name"] != "pqcsuite"}
        a, b = deps(old), deps(sbom)
        change = [f"+ {n} {b[n]}" for n in sorted(b.keys() - a.keys())] + [f"- {n} {a[n]}" for n in sorted(a.keys() - b.keys())] + [
            f"{n} {a[n]} to {b[n]}" for n in sorted(a.keys() & b.keys()) if a[n] != b[n]]
        lines.append(f"| Dependencies (SBOM) | {'; '.join(change) or 'no change'} |")
    else:
        lines.append(f"| Dependencies (SBOM) | {prev['tag_name']} has no SBOM to compare with |")
    old = asset(prev, "-cbom.json")
    if old:
        crypto = lambda d: {c["name"] for c in d.get("components", [])}
        a, b = crypto(old), crypto(cbom)
        change = [f"+ {n}" for n in sorted(b - a)] + [f"- {n}" for n in sorted(a - b)]
        lines.append(f"| Cryptography in the code (CBOM) | {'; '.join(change) or 'no change'} |")
    return "\n".join(lines)


def outstanding():
    text = (ROOT / "docs" / "RELEASE-READINESS.md").read_text(encoding="utf-8")
    return re.search(r"^## Not yet validated\n(.*?)(?=^## |\Z)", text, re.M | re.S).group(1).strip()


def report(tag, sha, evidence, latest, changes=""):
    lines, ok = [], True
    for gate, checks in GATES.items():
        lines += [f"\n### {gate}\n", "| Check | Jobs | Result |", "|---|---|---|"]
        for what, name, count in checks:
            jobs = [r for n, r in sorted(latest.items()) if matches(n, name)]
            passed = len(jobs) >= count and all(r["conclusion"] == "success" for r in jobs)
            ok &= passed
            result = "passed" if passed else "FAILED: " + ", ".join(f"{r['name']} {r['conclusion'] or r['status']}" for r in jobs) if jobs else "MISSING"
            links = ", ".join("[{name}]({html_url})".format(**r) for r in jobs) or "-"
            lines.append(f"| {what} | {links} | {result} |")
    e, b = evidence, evidence["benchmark"]
    hs = lambda g: "{median_ms} ms median, {p95_ms} ms p95".format(**b["tls_handshake_" + g])
    verdict = ("**Passed every automated gate** (correct, secure, operational in CI). That is not an external audit or a production "
               "deployment: see *Not yet validated*." if ok else "**Did not pass the gates; this commit must not be released.**")
    return ok, f"""# Release readiness: {tag}

Commit `{sha}`, checked {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M} UTC.

{verdict}
{chr(10).join(lines)}

### Evidence from this commit

| | |
|---|---|
| Tests (Debian 13, {e['openssl']}, Python {e['python']}) | {e['tests']} |
| Fuzz tests (seeded, in the suite) | {e['fuzz_tests']} |
| Crash, race, downgrade, recovery and secret-leak tests | {e['hostile_tests']} |
| Platforms in CI | Linux (Ubuntu, Debian 13 containers), Windows. macOS: not tested |
| OpenSSL | 3.5 or newer for TLS; {e['openssl']} here |
| SBOM | `pqcsuite-{tag.lstrip('v')}-sbom.json`, CycloneDX, {e['sbom_components']} components |
| CBOM | `pqcsuite-{tag.lstrip('v')}-cbom.json` (Wolf Pack) |
| Tested dependency versions | `pqcsuite-{tag.lstrip('v')}-constraints.txt`: `pip install -c` it to install exactly what this release was tested with |
| Build provenance | GitHub attestation on every release file |

### Performance on the GitHub runner (loopback, indicative only)

| | |
|---|---|
| TLS handshake, X25519MLKEM768 + ML-DSA-65 | {hs('X25519MLKEM768')} |
| TLS handshake, X25519 + ML-DSA-65 (classical key exchange) | {hs('X25519')} |
| Issue an ML-DSA-65 certificate | {b['ca_issue_ML-DSA-65']['median_ms']} ms median |
| Vault, 64 MiB | encrypt {b['vault_64MiB']['encrypt_MiB_s']} MiB/s, decrypt {b['vault_64MiB']['decrypt_MiB_s']} MiB/s |
| Load: {b['load']['clients']} clients for {b['load']['seconds']} s, one process | {b['load']['connections_per_s']} new post-quantum connections/s, median {b['load']['median_ms']} ms, p99 {b['load']['p99_ms']} ms, {b['load']['errors']} errors |

### Changes since the previous release

{changes or "Not compared (no SBOM and CBOM given)."}

## Not yet validated

{outstanding()}
"""


def evidence(out, sbom):
    import platform
    import subprocess
    import unittest
    sys.path.insert(0, str(ROOT))
    from pqcsuite import tls
    tests = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    flat = lambda s: [t for x in s for t in (flat(x) if isinstance(x, unittest.TestSuite) else [x])]
    modules = [type(t).__module__.rsplit(".", 1)[-1] for t in flat(tests)]
    with open(os.devnull, "w") as null:
        result = unittest.TextTestRunner(stream=null).run(tests)
    bench = subprocess.run([sys.executable, str(ROOT / "scripts" / "benchmark.py")], capture_output=True, text=True, check=True).stdout
    Path(out).write_text(json.dumps({
        "tests": f"{result.testsRun} run, {len(result.skipped)} skipped, {len(result.failures) + len(result.errors)} failed",
        "fuzz_tests": modules.count("test_fuzz"),
        "hostile_tests": sum(m in ("test_crash", "test_races", "test_downgrade", "test_recovery", "test_secrets") for m in modules),
        "openssl": tls.lib().version, "python": platform.python_version(),
        "sbom_components": len(json.loads(Path(sbom).read_text()).get("components", [])), "benchmark": json.loads(bench)}, indent=1))
    return result.wasSuccessful()


if __name__ == "__main__":
    if sys.argv[1:2] == ["evidence"] and len(sys.argv) == 4:
        sys.exit(0 if evidence(*sys.argv[2:]) else 1)
    if sys.argv[1:2] != ["report"] or len(sys.argv) not in (6, 8):
        raise SystemExit(__doc__)
    tag, sha, ev, out = sys.argv[2:6]
    changes = ""
    if len(sys.argv) == 8:
        try:
            changes = since(tag, *(json.loads(Path(f).read_text()) for f in sys.argv[6:8]))
        except (OSError, ValueError, KeyError) as e:  # a missing comparison is reported, it does not block the release
            changes = f"Not compared: {e}"
    ok, text = report(tag, sha, json.loads(Path(ev).read_text()), runs(sha), changes)
    Path(out).write_text(text, encoding="utf-8")
    print(text)
    sys.exit(0 if ok else 1)
