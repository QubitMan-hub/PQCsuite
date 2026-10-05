"""The commands for the whole suite: doctor, setup, try and the console."""
import json
import logging
import sys
import threading
from pathlib import Path

from .. import NAME, __version__, explain, tls
from ..pki import CA
from .common import run_until_signal


def cmd_doctor(a):
    if getattr(a, 'json', False):
        from .. import checks
        rows = checks.prerequisites(a.product)
        rows += [{'product': 'deployment', 'level': level, 'message': message, 'action': ''}
                 for level, message in ([r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)] + [r for d in a.backups for r in checks.backups(d)])]
        print(json.dumps({'version': __version__, 'checks': rows}, indent=2))
        return 2 if any(r['level'] == 'fail' for r in rows) else 1 if a.strict and any(r['level'] == 'warn' for r in rows) else 0
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    print(f"{NAME} {__version__}, Python {sys.version.split()[0]}")
    print(f"CA and Vault: ready (cryptography {cryptography.__version__}, with its own {backend.openssl_version_text()})")
    try:
        lib = tls.lib()
        ctx = tls.client_context(verify=False)  # wolfpack:ignore (only checks that a context can be built; nothing connects)
        ctx.close()
        print(f"TLS edge, VPN key agreement and readiness scans: ready (this machine's {lib.version}; groups {tls.PQC_GROUPS})")
        broken = False
    except tls.TLSError as e:
        print(f"TLS edge, VPN key agreement and readiness scans: not available: {e}")
        broken = a.product in ('all', 'tls', 'vpn')
    from .. import checks
    names = {'repository': 'Repository scans', 'vpn': 'VPN'}
    rows = [r for r in checks.prerequisites(a.product) if r['product'] in names]
    for r in rows:
        print(f"{names[r['product']]}: {r['message']}" + (f". {r['action']}" if r['action'] else ''))
    broken = broken or (a.product != 'all' and any(r['level'] == 'fail' for r in rows))
    fails = warns = 0
    if a.check_updates:
        from .. import latest_release
        try:
            latest = latest_release()
        except (OSError, ValueError) as e:
            print(f"updates: cannot check: {explain(e) if isinstance(e, OSError) else e}")
        else:
            print(f"updates: {latest['version']} is out: {latest['url']}" if latest and latest["newer"] else f"updates: {__version__} is the newest release")
    if a.ca or a.config or a.backups:
        results = ([r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)]
                   + [r for d in a.backups for r in checks.backups(d)])
        mark = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
        for level, msg in results:
            print(f"{mark[level]}  {msg}")
        fails, warns = sum(r[0] == "fail" for r in results), sum(r[0] == "warn" for r in results)
        print(f"\n{fails} problem(s), {warns} warning(s)")
    return 3 if broken else 2 if fails else 1 if warns and a.strict else 0


def cmd_setup(a):
    from .. import checks
    from ..storage import locked, write
    project = Path(a.project).resolve()
    if not project.is_dir():
        raise ValueError('Choose an existing repository folder with --project')
    rows = checks.prerequisites('repository')
    for row in rows:
        print(f"{row['level'].upper()}: {row['message']}" + (f". {row['action']}" if row['action'] else ''))
    if any(r['level'] == 'fail' for r in rows):
        return 2
    destination = Path(a.out).absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings = {'listen': '127.0.0.1:8900', 'project_roots': [str(project)],
                'project_state': str(destination.parent/'projects.json'), 'audit_log': str(destination.parent/'console-audit.jsonl')}
    content = '[console]\n' + ''.join(f'{key} = {json.dumps(value)}\n' for key, value in settings.items())
    with locked(destination.parent, '.setup.lock'):
        if destination.exists() or destination.is_symlink():
            raise ValueError('Setup preserves existing configuration; choose another --out path or use the existing console configuration')
        write(destination, content.encode(), secret=True)
    print(f'Configured repository: {project}')
    print(f'Next: pqcsuite console --config "{destination}"')
    print('Open the local address, use the startup token, then select Scan project. Results and remediation are saved privately.')
    print('For a device certificate: pqcsuite ca enroll --guide --out device')
    return 0


def cmd_try(a):
    """A self-contained tour, nothing to set up: a CA, a plain web server, the post-quantum edge in front of it, a
    post-quantum client that gets through and a classical one that does not. Everything lives in a temporary folder."""
    import tempfile
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from ..tls.edge import Edge, Route
    from ..tls.openssl import Context
    tls.lib()  # say at once when this machine's OpenSSL cannot do post-quantum TLS, not halfway through the tour

    class Hello(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"Hello from a web server that knows nothing about post-quantum cryptography\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    logging.getLogger(NAME).setLevel(logging.ERROR)
    step = lambda n, text: print(f"\n{n}. {text}")
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        step(1, "A private certificate authority (ML-DSA-87 root) issues the edge an ML-DSA-65 certificate.")
        ca = CA.init(d / "pki", "Try Root")
        ca.issue("localhost", "server", ["127.0.0.1"], out=d / "edge")
        web = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        step(2, f"An ordinary web server starts on 127.0.0.1:{web.server_address[1]}. It has no post-quantum support.")
        edge = Edge(Route("try", "terminate", "127.0.0.1:0", f"127.0.0.1:{web.server_address[1]}", cert=str(d / "edge" / "chain.pem"),
                          key=str(d / "edge" / "key.pem"))).start()
        try:
            step(3, f"The pqcsuite edge starts in front of it on 127.0.0.1:{edge.port}, accepting post-quantum clients only.")
            step(4, "A post-quantum client asks for the page through the edge:")
            with tls.connect("127.0.0.1", edge.port, tls.client_context(d / "pki" / "ca.crt"), "localhost", 10) as c:
                c.sendall(b"GET / HTTP/1.0\r\n\r\n")
                reply = b""
                while chunk := c.recv(timeout=10):
                    reply += chunk
                info = c.info()
            print(f"   key exchange  {info['group']}   (post-quantum: X25519 combined with ML-KEM-768)")
            print(f"   certificate   {info['peer_key']}   (post-quantum signature)")
            page = reply.split(b"\r\n\r\n", 1)[-1].decode().strip()
            print(f"   page          {page}")
            step(5, "A client that only knows classical key exchange (X25519) tries the same:")
            # wolfpack:ignore (a classical client on purpose: the tour shows the edge refusing it)
            classical = Context(False, "X25519", None, tls.CIPHERSUITES, None, None, None, str(d / "pki" / "ca.crt"), True)
            try:
                tls.connect("127.0.0.1", edge.port, classical, "localhost", 10).close()
                print("   it got through, which it should not have")
                return 1
            except (tls.TLSError, OSError):
                print("   refused, as it should be: no connection falls back to a key exchange a future quantum computer could break")
            classical.close()
        finally:
            edge.stop(0)
            web.shutdown()
            web.server_close()
    print("\nThat is the TLS product: post-quantum protection in front of a service that did not change.\n"
          "Next: pqcsuite tls edge --help, and https://qubitman-hub.github.io/PQCsuite/")
    return 0


def cmd_console(a):
    from ..console import App, Settings, serve
    s = Settings.load(a.config) if a.config else Settings()
    for k in ("listen", "ca"):
        if getattr(a, k):
            setattr(s, k, getattr(a, k))
    s.edges += a.edge
    s.vpn += a.vici
    s.wireguard += a.wireguard
    s.backups += a.backups
    s.scan_targets += a.scan
    s.project_roots += a.project
    s.project_state = a.project_state or s.project_state or ".pqcsuite/projects.json"
    if a.project_history:
        s.project_history = a.project_history
    if a.repositories:
        s.repository_directory = a.repositories
    if a.scan_every is not None:
        s.scan_every_hours = a.scan_every
    s.check_updates = s.check_updates or a.check_updates
    if s.ca and not (Path(s.ca) / "ca.crt").exists():
        raise ValueError(f"no CA at {s.ca}; run 'pqcsuite ca init' first, or leave out --ca")
    if a.sample_project:
        from ..project import sample_project, scanner
        scanner()
        s.project_roots.append(str(sample_project(Path(s.project_state).parent)))
    app = App(s)
    httpd = serve(app)
    host, port = httpd.server_address[:2]
    print(f"console on http://{host}:{port}/  access token: {app.token}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print("warning: listening beyond localhost over plain HTTP; put `pqcsuite tls edge --policy transition` in front of it")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    app.schedule()
    stop = threading.Event()
    run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    return 0

def add(sub):
    p = sub.add_parser("doctor", help="check that this machine can run everything",
                       epilog="exit codes: 0 safe, 1 warnings (with --strict), 2 unsafe configuration, 3 broken installation")
    p.set_defaults(func=cmd_doctor)
    p.add_argument("--json", action="store_true", help="structured local prerequisite checks and actionable diagnostics")
    p.add_argument("--product", choices=["all", "repository", "tls", "vault", "vpn"], default="all", help="only this product's checks")
    p.add_argument("--check-updates", action="store_true", help="also ask GitHub whether a newer release is out (the only request it makes)")
    p.add_argument("--ca", action="append", default=[], metavar="DIR", help="check a CA: key protection, CRL freshness, certificates expiring")
    p.add_argument("--backups", action="append", default=[], metavar="DIR",
                   help="check a folder of Vault archives: readable, opened by two or more keys, newest recent")
    p.add_argument("--strict", action="store_true", help="warnings fail too (exit 1); a deployment gate")
    p.add_argument("--config", action="append", default=[], metavar="FILE",
                   help="check an edge, VPN, WireGuard or console configuration: it loads, its files exist, nothing weakens it")

    p = sub.add_parser("setup", help="check prerequisites and prepare a private repository console")
    p.set_defaults(func=cmd_setup)
    p.add_argument("--project", default=".", help="repository folder to scan")
    p.add_argument("--out", default=".pqcsuite/console.toml", help="new configuration file; existing files are preserved")

    p = sub.add_parser("try", help="a one-minute tour: the post-quantum edge in front of a web server, nothing to set up")
    p.set_defaults(func=cmd_try)

def add_console(sub):
    p = sub.add_parser("console", help="one dashboard for all four products")
    p.set_defaults(func=cmd_console)
    p.add_argument("--config", help="TOML with a [console] section")
    p.add_argument("--listen", help="default 127.0.0.1:8900")
    p.add_argument("--ca", help="CA folder")
    p.add_argument("--edge", action="append", default=[], help="an edge's metrics address, e.g. http://127.0.0.1:9100 (repeatable)")
    p.add_argument("--vici", action="append", default=[], help="strongSwan VICI address (repeatable)")
    p.add_argument("--wireguard", action="append", default=[], help="a WireGuard gateway's metrics address (repeatable)")
    p.add_argument("--backups", action="append", default=[], help="folder of vault archives (repeatable)")
    p.add_argument("--scan", action="append", default=[], metavar="HOST:PORT", help="an endpoint for readiness scans (repeatable)")
    p.add_argument("--project", action="append", default=[], help="allow scanning this local project folder (repeatable; no source upload)")
    p.add_argument("--repositories", help="administrator-approved parent folder for Add repository in the console")
    p.add_argument("--sample-project", action="store_true", help="create a local example repository for the readiness workflow; preserve existing edits")
    p.add_argument("--project-state", help="private persistent repository/assessment workspace (default: .pqcsuite/projects.json)")
    p.add_argument("--project-history", help="persist bounded project scan summaries to this private JSON file")
    p.add_argument("--scan-every", type=float, metavar="HOURS", help="scan those endpoints again every HOURS and show what changed")
    p.add_argument("--check-updates", action="store_true", help="show when a newer release is out (asks GitHub once a day)")
