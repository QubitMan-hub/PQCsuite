"""Writes site/console-demo.html: the real console page, with every request it makes answered from a recording of a real
console looking after invented systems (Example Bank's certificate authority, an edge, two scanned endpoints, backups and
an example application). Nothing is scanned or sent from the visitor's browser; buttons that would change something say
the demo is read-only. Machine paths and local addresses are replaced by example names. Needs OpenSSL 3.5.

    python scripts/console_demo.py
"""
import importlib.util
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "wolf-pack")]
from pqcsuite import vault  # noqa: E402
from pqcsuite.console import App, Settings, page  # noqa: E402
from pqcsuite.pki import CA  # noqa: E402

spec = importlib.util.spec_from_file_location("sample", ROOT / "examples" / "readiness-sample" / "make_report.py")
sample = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sample)

READ_ONLY = "This demo shows example data, so changes are switched off. Install PQC Suite to use the console on your own systems."
SHIM = """<script>
const DEMO = __DATA__;
window.fetch = async (url, options = {}) => {
  const key = (options.method || "GET").toUpperCase() + " " + String(url).replace(/^\\/api\\//, "");
  const known = Object.prototype.hasOwnProperty.call(DEMO, key);
  return new Response(JSON.stringify(known ? DEMO[key] : { error: __READ_ONLY__ }), { status: known ? 200 : 403, headers: { "Content-Type": "application/json" } });
};
</script>"""
BANNER = """<p class="demo-bar" role="note"><b>Demo</b> with invented example data. Nothing is scanned or sent from your browser.
<a href="index.html#use">Install it</a></p>
<style>.demo-bar{position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:50;margin:0;padding:10px 16px;border-radius:999px;
background:#1f2a37;color:#f2f4f6;font:500 14px/1.3 "Segoe UI",system-ui,sans-serif;box-shadow:0 12px 30px -12px rgba(0,0,0,.5);
white-space:nowrap;max-width:calc(100vw - 32px);overflow:hidden;text-overflow:ellipsis}.demo-bar b{color:#ffbf00;margin-right:4px}
.demo-bar a{color:#ffcf4d;margin-left:10px}</style>"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(predicate, seconds=120):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > deadline:
            raise SystemExit("the example console did not finish in time")
        time.sleep(0.3)


def main():
    logging.disable(logging.WARNING)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        ca = CA.init(d / "pki", "Example Bank Root", passphrase=None)
        for kind, name, days in (("server", "api.examplebank.test", 397), ("server", "portal.examplebank.test", 397), ("client", "payments-batch", 397),
                                 ("client", "branch-042", 397), ("server", "reports.examplebank.test", 12), ("client", "laptop-alice", 397)):
            ca.issue(name, kind, days=days, out=d / name)
        lost = next(r for r in ca.records() if r.common_name == "laptop-alice")
        ca.revoke(lost.serial, "keyCompromise")
        ca.crl()
        web = ThreadingHTTPServer(("127.0.0.1", 0), sample.Hello)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        edge_port, metrics = free_port(), free_port()
        edge = subprocess.Popen([sys.executable, "-m", "pqcsuite", "tls", "edge", "--listen", f"127.0.0.1:{edge_port}", "--target", f"127.0.0.1:{web.server_address[1]}",
                                 "--cert", str(d / "api.examplebank.test" / "chain.pem"), "--key", str(d / "api.examplebank.test" / "key.pem"),
                                 "--metrics", f"127.0.0.1:{metrics}"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ | {"PYTHONPATH": str(ROOT)})
        legacy = sample.classical_server(*sample.classical_cert(d, "switch", sample.rsa.generate_private_key(public_exponent=65537, key_size=2048)))
        backups = d / "backups"
        backups.mkdir()
        ops, recovery = vault.Identity.generate(), vault.Identity.generate()
        for name in ("ledger-2026-10-03", "ledger-2026-10-04", "statements-2026-10-05"):
            (d / f"{name}.csv").write_text("date,amount\n2026-10-01,1200\n")
            vault.encrypt(d / f"{name}.csv", backups / f"{name}.pqv", [ops.public, recovery.public])
        project = d / "projects" / "payments-api"
        shutil.copytree(ROOT / "examples" / "wolfpack-sample" / "payments-api", project)
        names = {f"127.0.0.1:{edge_port}": "api.examplebank.test:443", f"127.0.0.1:{legacy.server_address[1]}": "payments-switch.examplebank.test:443",
                 f"http://127.0.0.1:{metrics}": "http://edge-1.examplebank.test:9100", f"127.0.0.1:{web.server_address[1]}": "10.0.4.20:8080",
                 str(d): "/srv/example-bank"}
        try:
            wait(lambda: socket.socket().connect_ex(("127.0.0.1", metrics)) == 0, 30)
            app = App(Settings(ca=str(d / "pki"), edges=[f"http://127.0.0.1:{metrics}"], backups=[str(backups)], project_roots=[str(project)],
                               project_state=str(d / "projects.json"), audit_log=str(d / "audit.jsonl"), scan_targets=list(names)[:2]))
            app.handle("POST", "/api/scan", {"targets": "\n".join(list(names)[:2])})
            wait(lambda: not app.scanning)
            app.handle("POST", "/api/projects/scan", {"project": 0})
            wait(lambda: not app.handle("GET", "/api/projects/status", None)[1]["running"])
            recorded = {}
            for path in ("overview", "certificates", "edges", "tunnels", "remote", "backups", "projects", "projects/status", "scan"):
                status, body = app.handle("GET", f"/api/{path}", None)
                if status != 200:
                    raise SystemExit(f"/api/{path} answered {status}: {body}")
                recorded[f"GET {path}"] = body
            recorded["POST scan"] = {"started": True}
            recorded["POST projects/scan"] = {"started": True}
            recorded["POST projects/select"] = {"selected": True}
        finally:
            edge.terminate()
            legacy.shutdown()
            web.shutdown()
        data = json.dumps(recorded, default=str)
        for real, example in sorted(names.items(), key=lambda kv: -len(kv[0])):
            data = data.replace(real, example)
        for leak in (tmp, "127.0.0.1", socket.gethostname()):
            if leak in data:
                at = data.index(leak)
                raise SystemExit(f"the recording still contains {leak!r} ({data[max(0, at - 120):at + 60]}); add it to the replacements")
    html = page().decode()
    html = html.replace('try { token = sessionStorage.getItem("pqc-token"); } catch (e) {}', 'token = "demo";', 1)
    html = html.replace("<title>", '<meta name="robots" content="noindex">\n<title>', 1)
    for real, demo in (('Tour.start("console", TOUR)', 'Tour.start("console-demo", TOUR)'), ('Tour.offer("console", TOUR)', 'Tour.offer("console-demo", TOUR)'),
                       ("This is where you run the four Acxelin products on this server.",
                        "This demo shows the console with invented example data, so you can look around without installing anything."),
                       ("Tour replays this guide, Theme switches light and dark, and Sign out ends your session. Your work stays on this server.",
                        "Tour replays this guide and Theme switches light and dark. Buttons that would change something are switched off in the demo; "
                        "install PQC Suite to run the console on your own systems.")):
        if real not in html:
            raise SystemExit(f"the console no longer contains {real!r}; update the demo's tour wording")
        html = html.replace(real, demo, 1)
    shim = SHIM.replace("__DATA__", data.replace("</", "<\\/")).replace("__READ_ONLY__", json.dumps(READ_ONLY))
    html = html.replace("<body>", "<body>\n" + BANNER + "\n" + shim, 1)
    (ROOT / "site" / "console-demo.html").write_text(html, encoding="utf-8")
    print("wrote site/console-demo.html")


if __name__ == "__main__":
    main()
