import argparse
import getpass
import json
import logging
import os
import signal
import socket
import sys
import threading
from pathlib import Path

from . import JSON, METRICS, NAME, PEM, ConfigWatch, __version__, env_passphrase, explain, restart, serve_http, tls
from .pki import ALGORITHMS, CA, CA_ALGORITHMS, REASONS, CAError, encrypted
from .vault import VaultError
from .vpn.charon import CharonError
from .vpn.wireguard import WGError

CA_PASS_ENV = "PQCSUITE_CA_PASSPHRASE"


def ask(prompt, instead):
    """A passphrase typed at the terminal; without one (a pipe, a service, CI) a clear error naming the alternative."""
    try:
        if not sys.stdin.isatty():
            raise EOFError
        return getpass.getpass(prompt).encode()
    except EOFError:
        raise ValueError(f"no terminal to type the passphrase in: {instead}") from None


def ca_passphrase(root, new=False):
    """From PQCSUITE_CA_PASSPHRASE or a prompt, and only when the CA key is (or will be) encrypted."""
    if not new and not encrypted(Path(root) / "ca.key"):
        return None
    if os.environ.get(CA_PASS_ENV):
        return os.environ[CA_PASS_ENV].encode()
    if not new:
        return ask("CA passphrase: ", f"set {CA_PASS_ENV}")
    instead = f"set {CA_PASS_ENV}, or pass --no-encrypt to leave the CA key unencrypted"
    p1, p2 = ask("New CA passphrase: ", instead), ask("Repeat: ", instead)
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1


def show(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=1, default=str))
    else:
        for k, v in obj.items():
            print(f"{k:>14}  {', '.join(map(str, v)) if isinstance(v, (list, tuple)) else 'none' if v is None else v}")


def cmd_doctor(a):
    if getattr(a, 'json', False):
        from . import checks
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
        broken = True
    from . import checks
    names = {'repository': 'Repository scans', 'vpn': 'VPN'}
    rows = [r for r in checks.prerequisites(a.product) if r['product'] in names]
    for r in rows:
        print(f"{names[r['product']]}: {r['message']}" + (f". {r['action']}" if r['action'] else ''))
    broken = broken or (a.product != 'all' and any(r['level'] == 'fail' for r in rows))
    fails = warns = 0
    if a.check_updates:
        from . import latest_release
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
    from . import checks
    from .storage import locked, write
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


def cmd_ca(a):
    if a.ca_cmd == "init":
        parent = None
        if a.parent:
            pw = None
            if encrypted(Path(a.parent) / "ca.key"):
                pw = os.environ.get("PQCSUITE_PARENT_CA_PASSPHRASE", "").encode() or ask("Parent CA passphrase: ", "set PQCSUITE_PARENT_CA_PASSPHRASE")
            parent = CA(a.parent, pw)
        if a.signer_command and not a.signer_public_key:
            raise CAError("--signer-command needs --signer-public-key")
        signer = ({"type": "aws-kms", "key_id": a.kms, **({"region": a.kms_region} if a.kms_region else {})} if a.kms else
                  {"type": "command", "command": a.signer_command, "public_key": str(Path(a.signer_public_key).resolve())} if a.signer_command else None)
        ca = CA.init(a.dir, a.name, a.algorithm, a.days, ca_passphrase(a.dir, new=True) if not (a.no_encrypt or signer) else None, parent, signer)
        what = f"intermediate CA under '{parent.cert.subject.rfc4514_string()}'" if parent else "root"
        print(f"created {ca.algorithm} {what} '{a.name}' in {a.dir} (serial {ca.cert.serial_number:x}); clients trust {ca.anchor}, servers check {Path(a.dir) / 'crl.pem'}")
        return 0
    ca = CA(a.dir, None if a.ca_cmd in ("list", "publish") else ca_passphrase(a.dir))
    if a.ca_cmd == "issue":
        out, r = ca.issue(a.common_name, a.kind, a.san, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"issued {r.kind} certificate {r.serial} for {r.common_name} ({r.algorithm}), valid until {r.not_after}")
        print(f"  {out / 'cert.pem'}\n  {out / 'chain.pem'}  (certificate + CA: what servers and mTLS clients present)\n  {out / 'key.pem'}")
    elif a.ca_cmd == "sign-csr":
        cert, r = ca.sign_csr(Path(a.csr).read_bytes(), a.kind, a.days)
        from .pki import cert_pem
        Path(a.out).write_bytes(cert_pem(cert))
        print(f"signed {r.serial} for {r.common_name} -> {a.out}")
    elif a.ca_cmd == "revoke":
        ca.revoke(a.serial, a.reason)
        print(f"revoked {ca.find(a.serial).serial}; {Path(a.dir) / 'crl.pem'} updated (servers with crl_url fetch it from 'ca publish'; copy it to any others)")
    elif a.ca_cmd == "crl":
        ca.crl(a.days)
        print(f"wrote {Path(a.dir) / 'crl.pem'}")
    elif a.ca_cmd == "renew":
        out, r = ca.renew(a.serial, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"renewed as {r.serial}, valid until {r.not_after}, in {out}")
    elif a.ca_cmd == "token":
        from .pki.est import create_token
        t = create_token(ca, a.common_name, a.kind, a.san, a.hours)
        print(f"one-time enrollment token for {a.common_name} ({a.kind}), valid {a.hours} h. It is shown only once:\n{t}")
    elif a.ca_cmd == "serve":
        from cryptography.x509 import load_pem_x509_certificate
        from .pki.est import fingerprint, serve
        srv = serve(a.dir, a.listen, a.cert, a.key, ca_passphrase(a.dir), env_passphrase(a.key_passphrase_env))
        print(f"EST enrollment on https://{a.listen}/.well-known/est; CA fingerprint (give it to clients):\n{fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes()))}")
        run_until_signal(srv.serve_forever, srv.stop)
    elif a.ca_cmd == "publish":
        crl, anchor = Path(a.dir) / "crl.pem", ca.anchor
        read = lambda f: lambda: f.read_text(encoding="ascii") if f.exists() else None
        httpd = serve_http(a.listen, {"/crl.pem": (PEM, read(crl)), "/ca.crt": (PEM, read(anchor))})
        host, port = httpd.server_address[:2]
        print(f"publishing http://{host}:{port}/crl.pem (read fresh on every request) and /ca.crt; set crl_url to it on edges and gateways")
        stop = threading.Event()
        run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    elif a.ca_cmd == "maintain":
        renewed, skipped = ca.maintain(a.renew_within, a.crl_days)
        for r in renewed:
            print(f"renewed {r.common_name} -> {r.serial[:16]} in {r.path}, valid until {r.not_after[:10]}")
        for r in skipped:
            print(f"NOT renewed {r.common_name} ({r.serial[:16]}, expires {r.not_after[:10]}): its key is encrypted; renew it by hand")
        print(f"CRL re-signed, valid {a.crl_days} days")
        return 1 if skipped else 0
    elif a.ca_cmd == "list":
        rows = ca.expiring(a.expiring) if a.expiring is not None else ca.records()
        if a.json:
            print(json.dumps([vars(r) for r in rows], indent=1))
        for r in [] if a.json else rows:
            print(f"{r.serial[:16]:16}  {r.status:7}  {r.kind:6}  {r.not_after[:10]}  {r.algorithm:9}  {r.common_name}  {' '.join(r.names)}")
    return 0


def cmd_tls(a):
    if a.tls_cmd == "serve":
        from .tls.server import Server
        make = lambda: tls.server_context(a.cert, a.key, a.ca, a.require_client_cert, a.policy, env_passphrase(a.key_passphrase_env))

        def echo(conn, addr):
            while data := conn.recv(timeout=300):
                conn.sendall(data)

        srv = Server(tls.hostport(a.listen), make, echo, watch=[a.cert, a.key, a.ca], crl=a.crl, ca=a.ca, name="serve")
        run_until_signal(srv.serve_forever, srv.stop)
        return 0
    host, port = tls.hostport(a.target, "")
    ctx = tls.client_context(a.ca, a.cert, a.key, a.policy, env_passphrase(a.key_passphrase_env))
    try:
        conn = tls.connect(host, port, ctx, a.server_name, a.timeout)
    except socket.gaierror as e:
        raise tls.TLSError(f"{host}: {explain(e)}; connect by address and name the certificate with --server-name {host}") from None
    with conn:
        out = conn.info()
        if a.send is not None:
            try:
                conn.sendall(a.send.encode())
                reply = conn.recv()
                while reply and (more := _more(conn)):
                    reply += more
            except (tls.TLSError, OSError) as e:
                reply, out["error"] = b"", explain(e)
            if not reply:
                raise tls.TLSError("the server closed the connection right after the handshake: either it refused our client certificate "
                                   "(missing, untrusted or revoked), or the service behind it is down (see the server's log)"
                                   f"{': ' + out['error'] if out.get('error') else ''}")
            out["reply"] = reply.decode(errors="replace")
    show(out, a.json)
    return 0


def _more(conn):
    """The rest of a reply that arrives in several pieces: read until the server closes or is quiet for a second."""
    try:
        return conn.recv(timeout=1.0)
    except (tls.TLSError, OSError):
        return b""


def cmd_probe(a):
    from .readiness.scan import GRADES, probe
    r = probe(a.target, a.server_name, a.timeout)
    r["verdict"] = f"{r['grade']}: {GRADES[r['grade']]}"
    show(r, a.json)
    return 0 if r["grade"] in "AB" else 2


def cmd_scan(a):
    from .readiness import scan
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


def cmd_edge(a):
    from .tls.edge import WORKER, Edge, Route, Workers, load_config, reconcile, report, serve_metrics
    if not (a.config or a.target):
        raise ValueError("edge needs --config or --target")
    if a.config:
        routes, metrics = load_config(a.config)
    else:
        routes = [Route(name="edge", mode=a.mode, listen=a.listen, target=a.target, policy=a.policy, cert=a.cert or "", key=a.key or "",
                        key_passphrase_env=a.key_passphrase_env or "", ca=a.ca or "", require_client_cert=a.require_client_cert,
                        crl=a.crl or "", crl_url=a.crl_url or "", server_name=a.server_name or "", proxy_protocol=a.proxy_protocol,
                        fallback_cert=a.fallback_cert or "", fallback_key=a.fallback_key or "")]
        metrics = a.metrics
    if a.workers < 1:
        raise ValueError("--workers must be 1 or more")
    worker = bool(os.environ.get(WORKER))
    shared = a.workers > 1 or worker
    if shared:
        if any(tls.hostport(r.listen)[1] == 0 for r in routes):
            raise ValueError("--workers needs a fixed listen port, not 0")
        if not sys.platform.startswith("linux"):
            raise ValueError("--workers needs Linux, where the kernel spreads connections over the processes (SO_REUSEPORT)")
    edges = [Edge(r).bind(reuse_port=shared) for r in routes]
    workers = Workers(a.workers) if a.workers > 1 and not worker else None
    if worker:
        threading.Thread(target=report, args=(edges,), daemon=True).start()
    elif metrics:
        serve_metrics(metrics, edges, workers)
    for e in edges:
        threading.Thread(target=e.serve_forever, daemon=True, name=e.route.name).start()
    watch = ConfigWatch(a.config, load_config, lambda new: reconcile(edges, new[0], shared)) if a.config else None
    done = threading.Event()

    def stop():
        if watch:
            watch.stop()
        for e in list(edges):
            e.stop()
        if workers:
            workers.stop()
        done.set()
    run_until_signal(done.wait, stop, watch.poke if watch else None)
    return 0


def cmd_vpn(a):
    from .vpn import load_config
    from .vpn.charon import Charon
    if a.vpn_cmd in ("gateway", "connect", "disconnect", "install", "uninstall"):
        return cmd_wireguard(a)
    if a.vpn_cmd == "up":
        from .vpn.controller import Controller
        site = load_config(a.config)
        ctl = Controller(site)
        ctl.start()
        if site.metrics:
            serve_http(site.metrics, {"/metrics": (METRICS, ctl.metrics), "/status": (JSON, lambda: json.dumps(ctl.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, load_config, lambda new: new != site and (again.set(), ctl.shutdown()))
        run_until_signal(ctl.stop.wait, ctl.shutdown, watch.poke)
        if again.is_set():
            restart()
        return 0
    if a.vpn_cmd == "status" and not (a.config or a.vici):
        from .vpn import platforms
        path = platforms.folder() / f"{a.interface}.status.json"
        if path.exists():
            return laptop_status(path, a)
    if a.vpn_cmd in ("invite", "join", "app", "desktop"):
        return {"invite": cmd_invite, "join": cmd_join, "app": cmd_app, "desktop": cmd_desktop}[a.vpn_cmd](a)
    try:
        ch = Charon(load_config(a.config).vici if a.config else a.vici or "unix:///var/run/charon.vici")
    except CharonError:
        if a.vpn_cmd != "status" or a.config or a.vici:
            raise
        print("Not connected. No VPN client is running on this machine and no strongSwan site is reachable here.\n"
              "Laptop: pqcsuite vpn join YOUR.pqcinvite (administrator terminal). Gateway: start strongSwan, or give --config or --vici.")
        return 1
    if a.vpn_cmd == "check":
        kems = ch.ml_kem()
        print(f"{ch.version()} at {ch.uri}\nML-KEM key exchanges: {', '.join(kems) or 'none (needs strongSwan 6.0.2+ with OpenSSL 3.5+ or the ml plugin)'}")
        return 0 if kems else 1
    tunnels = ch.tunnels()
    if a.json:
        print(json.dumps(tunnels, indent=1))
    elif not tunnels:
        print("no tunnels")
    for t in [] if a.json else tunnels:
        print(f"{t['peer']:16} {t['state']:12} {t['key_exchange']:32} PPK {'yes' if t['ppk'] else 'NO '}  up {t['established_s']}s")
        for c in t["children"]:
            print(f"  {c['name']:14} {c['state']:12} {c['encryption']:14} in {c['bytes_in']} B / out {c['bytes_out']} B")
    return 0


def laptop_status(path, a):
    import time
    s = json.loads(path.read_text(encoding="utf-8"))
    if s["state"] not in ("disconnected",) and time.time() - s.get("updated", 0) > 30:
        s |= {"state": "stopped", "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.get("updated", 0)))}
    print(json.dumps(s, indent=1) if a.json else describe_vpn(s, a.details))
    return 0 if s["state"] == "protected" else 1


def cmd_invite(a):
    import datetime as dt
    from cryptography.x509 import load_pem_x509_certificate
    from .pki.est import create_token, fingerprint
    tls.hostport(a.gateway)
    if not a.enroll.startswith("https://"):
        raise ValueError("--enroll must be the https:// address of `pqcsuite ca serve`")
    ca = CA(a.dir)
    token = create_token(ca, a.name, "client", hours=a.hours)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=a.hours)).replace(microsecond=0).isoformat()
    out = Path(a.out or f"{a.name}.pqcinvite")
    if out.exists():
        raise ValueError(f"{out} already exists; choose another --out")
    from .storage import write
    write(out, json.dumps({"pqcsuite_invite": 1, "name": a.name, "enroll": a.enroll, "ca_fingerprint": fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes())),
                           "gateway": a.gateway, "server_name": a.server_name, "expires": expires, "token": token}, indent=1).encode(), secret=True)
    print(f"wrote {out}: it lets {a.name} enroll once before {expires} and then connect to {a.gateway}.\n"
          f"Send it through a channel you trust (it holds a one-time token and the CA fingerprint the device will trust).\n"
          f"On the device, in an administrator terminal: pqcsuite vpn join {out.name}")
    return 0


def cmd_join(a):
    """Enroll from an invitation (if this machine has no certificate yet) and connect, asking only for the device key passphrase."""
    from .vpn import join
    inv = join.read(a.invitation)
    device = join.device_for(a.invitation, a.device)
    if not a.no_apply:
        join.preflight(f"pqcsuite vpn join {a.invitation}")
    enroll = join.must_enroll(inv, device)
    passphrase = env_passphrase(a.key_passphrase_env)
    if enroll:
        if passphrase is None:
            passphrase = ask("Choose a passphrase for this device's key: ", "supply --key-passphrase-env with a protected environment variable")
            if not passphrase or passphrase != ask("Repeat it: ", "supply --key-passphrase-env"):
                raise ValueError("the passphrases were empty or did not match; nothing was changed")
        print(f"Enrolling {inv['name']} with {inv['enroll']} (CA pinned by the invitation's fingerprint) ...", flush=True)
        cert = join.enroll(inv, device, a.invitation, passphrase)
        print(f"Enrolled: certificate valid until {cert.not_valid_after_utc.date()}, key encrypted in {device}. The invitation's one-time token is used up.", flush=True)
    elif passphrase is None and encrypted(device / "key.pem"):
        passphrase = ask("Device key passphrase: ", "supply --key-passphrase-env with a protected environment variable")
    return connect(a, inv["gateway"], device, passphrase, inv.get("server_name"))


def cmd_app(a):
    """The VPN window's service: a page on 127.0.0.1 behind a one-time address; this process holds the tunnel until stopped.
    With --session (how `vpn desktop` starts it, with administrator rights) the port and key come from the tray's file,
    output goes to a log next to it, and problems are shown in the window instead of ending the process."""
    import webbrowser
    from .storage import write
    from .vpn import app, join
    window = app.App(a.invitation, a.folder, interface=a.interface, apply=not a.no_apply)
    held, running = app.claim(window.folder, f"{a.interface}.app")
    if not held:
        if not running:
            raise ValueError(f"another `pqcsuite vpn app` holds {a.interface}; stop it, or use --interface")
        url = f"http://127.0.0.1:{running['port']}/#{app.request(running['port'], running['token'], 'POST', '/api/ticket')['ticket']}"
        print(f"The VPN window for {a.interface} is already running: {url}", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
        return 0
    port, record = 0, window.folder / f"{a.interface}.app.json"
    if a.session:
        session = json.loads(Path(a.session).read_text(encoding="utf-8"))
        window.token, port = session["token"], int(session["port"])
        log = os.fdopen(os.open(window.folder / f"{a.interface}.service.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
        for h in logging.getLogger().handlers:
            h.setStream(log)
    elif not a.no_apply:
        join.preflight("pqcsuite vpn app" + (f" {a.invitation}" if a.invitation else ""))
    srv = app.serve(window, ("127.0.0.1", port))
    window.on_quit = lambda: threading.Thread(target=srv.shutdown).start()
    port = srv.server_address[1]
    if not a.session:
        write(record, json.dumps({"port": port, "token": window.token}).encode(), secret=True)
    if a.session:
        logging.getLogger(NAME).info("VPN service for the desktop app on 127.0.0.1:%s", port)
    else:
        url = f"http://127.0.0.1:{port}/#{window.ticket()}"
        print(f"VPN window: {url}\nKeep this running; closing the window does not disconnect. Ctrl+C disconnects and stops it.", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
    try:
        run_until_signal(srv.serve_forever, window.on_quit)
    finally:
        window.disconnect()
        srv.server_close()
        if not a.session:
            record.unlink(missing_ok=True)
        held.close()
    return 0


def cmd_desktop(a):
    from .vpn import desktop
    if a.launcher or a.remove_launcher:
        path = desktop.launcher(remove=a.remove_launcher)
        print(f"removed {path}" if a.remove_launcher else f"added {desktop.NAME}: {path}")
        return 0
    if a.start_at_login:
        desktop.autostart(a.start_at_login == "on")
        print(f"{desktop.NAME} {'starts' if a.start_at_login == 'on' else 'no longer starts'} when you log in"
              + (" (the tray icon only; connecting still asks for your passphrase)" if a.start_at_login == "on" else ""))
        return 0
    return desktop.main(a.invitation, a.interface, not a.no_apply, a.background)


def cmd_wireguard(a):
    from .vpn import wireguard as wg
    if a.vpn_cmd == "gateway":
        gw = wg.Gateway(wg.load_gateway(a.config)).start()
        print(f"WireGuard gateway {gw.cfg.name} on {gw.cfg.interface}, key agreement on {gw.cfg.keyring_listen}, public key {gw.public}")
        if gw.cfg.metrics:
            serve_http(gw.cfg.metrics, {"/metrics": (METRICS, gw.metrics), "/status": (JSON, lambda: json.dumps(gw.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, wg.load_gateway, lambda new: gw.reconfigure(new) or (again.set(), gw.shutdown()))
        run_until_signal(gw.stop.wait, gw.shutdown, watch.poke)
        if again.is_set():
            restart()
        return 0
    from .vpn import platforms
    if a.vpn_cmd == "disconnect":
        tunnel, kill_switch = platforms.this_machine(a.interface)
        tunnel.down()
        kill_switch.off()
        print(f"{a.interface} is down and nothing is blocked any more")
        return 0
    if a.vpn_cmd == "uninstall":
        print(f"removed {platforms.uninstall()}; the VPN no longer starts with this machine (pqcsuite vpn disconnect takes it down now)")
        return 0
    if a.vpn_cmd == "install":
        if encrypted(Path(a.cert_dir) / 'key.pem'):
            raise ValueError('Built-in startup installation cannot unlock encrypted device keys; use interactive vpn connect or an administrator-managed service with --key-passphrase-env. Keep the key encrypted.')
        argv = [sys.executable, "-m", "pqcsuite", "vpn", "connect", a.keyring, "--cert-dir", str(Path(a.cert_dir).resolve()), "--interface", a.interface]
        argv += [*(["--ca", str(Path(a.ca).resolve())] if a.ca else []), *(["--server-name", a.server_name] if a.server_name else [])]
        wg.Client(a.keyring, a.cert_dir, a.interface, a.server_name, apply=False, ca=a.ca).agree()
        print(f"the gateway accepted this certificate; wrote {platforms.install(argv)}: the VPN now starts with this machine and restarts if it stops")
        return 0
    passphrase = env_passphrase(a.key_passphrase_env)
    if passphrase is None and encrypted(Path(a.cert_dir) / 'key.pem'):
        passphrase = ask('Device key passphrase: ', 'supply --key-passphrase-env with a protected environment variable')
    return connect(a, a.keyring, a.cert_dir, passphrase)


def connect(a, keyring, cert_dir, passphrase, server_name=None):
    from .vpn import wireguard as wg
    c = wg.Client(keyring, cert_dir, a.interface, server_name or getattr(a, "server_name", None), not a.no_apply, getattr(a, "config_out", None),
                  passphrase, ca=getattr(a, "ca", None), on_status=lambda s: print(describe_vpn(s), flush=True))
    if a.once:
        r = c.once()
        print(f"key agreement confirmed for {r['address']} through {r['endpoint']}; routes {', '.join(r['routes'])}; "
              f"{'no tunnel activated (--no-apply)' if a.no_apply else 'tunnel configured; verify a WireGuard handshake'}; "
              f"the PSK expires in about {r['rotate_s'] * 3}s; --once does not keep keys fresh")
        return 0
    print(f"Connecting to {keyring} as {c.name}. Keep this window open; Ctrl+C disconnects.", flush=True)
    run_until_signal(c.run, c.stop.set)
    c.close()
    return 0


def describe_vpn(s, details=False):
    """Plain words first (protected or not, and why); the algorithms underneath for anyone who asks."""
    state = s["state"]
    if state == "protected":
        scope = "All traffic (full tunnel, kill switch on)" if s["full_tunnel"] else f"Traffic to {', '.join(s['routes'])} (split tunnel)"
        lines = [f"Protected. {scope} goes through {s['gateway']} as {s['address']}."]
    elif state == "connecting":
        lines = [f"Connecting. Keys agreed with {s['gateway']}; waiting for the tunnel's first handshake."]
    elif state == "agreed":
        lines = [f"Keys agreed with {s['gateway']} for {s['address']}; no tunnel configured (--no-apply), so this machine is not protected."]
    elif state == "disconnected":
        lines = ["Disconnected. The tunnel is down and nothing is blocked."]
    elif state == "stopped":
        lines = [f"Not running. The VPN client last reported at {s['last_seen']}; start it again with `pqcsuite vpn join` or `pqcsuite vpn connect`."]
    else:
        lines = [f"Not protected. {s.get('error') or 'Not connected yet'}. Retrying automatically; full-tunnel traffic stays blocked meanwhile."]
    k = s.get("key_agreement")
    if k and (details or state == "protected"):
        kind = "Post-quantum" if k["post_quantum"] else "Classical (NOT post-quantum)"
        lines.append(f"  {kind} key agreement: TLS group {k['tls_group']}, gateway certificate {k['gateway_certificate']}; "
                     f"the WireGuard pre-shared key is renewed every {k['psk_rotation_s']} s")
    if details and k:
        age = s.get("handshake_age_s")
        lines.append(f"  last handshake {'never' if age is None else f'{age} s ago'}; next key in {s['next_key_s']} s; "
                     f"device {s['device']}; routes {', '.join(s['routes'])}")
    return "\n".join(lines)


def cmd_acme(a):
    from .pki import acme
    if a.ca_cmd == "csr":
        out = acme.make_csr(a.names, a.out, a.algorithm, env_passphrase(a.key_passphrase_env))
        print(f"{out / 'key.pem'} (keep secret), {out / 'csr.pem'} and {out / 'csr.der'}\n"
              f"certbot certonly --csr {out / 'csr.der'} --server https://ACME-HOST/directory ...")
        return 0
    if a.ca_cmd == "eab":
        kid, key = acme.create_eab(a.dir, a.note)
        print(f"external account binding for one client (shown once):\n  key id:   {kid}\n  HMAC key: {key}\n"
              f"certbot: --eab-kid {kid} --eab-hmac-key {key}")
        return 0
    ca = CA(a.dir, ca_passphrase(a.dir))
    ca.signer  # a wrong passphrase fails now, not at the first order
    base = a.base_url or f"{'https' if a.tls_cert else 'http'}://{a.listen}"
    httpd = acme.serve(acme.Service(ca, base, a.allow, a.require_eab, a.http_port, days=a.days, allow_local=a.allow_local_validation), a.listen, a.tls_cert, a.tls_key)
    print(f"ACME directory: {base}/directory (issuing ML-DSA certificates from {ca.cert.subject.rfc4514_string()})")
    run_until_signal(httpd.serve_forever, lambda: threading.Thread(target=httpd.shutdown).start())
    return 0


def cmd_vault(a):
    from . import vault
    def passphrase():
        if a.passphrase_env:
            return env_passphrase(a.passphrase_env)
        return ask("Key passphrase: ", "pass --passphrase-env VARIABLE") if encrypted(a.key) else None

    signer = lambda: vault.load_signer(a.sign_cert, a.sign_key, env_passphrase(a.sign_passphrase_env)) if a.sign_cert else None
    if a.vault_cmd == "keygen":
        taken = [f for f in (f"{a.out}.key", f"{a.out}.pub") if Path(f).exists()]
        if taken:
            raise VaultError(f"{taken[0]} already exists; pick another name (replacing a key makes everything encrypted to it unreadable)")
        ident = vault.Identity.generate(a.cnsa2)
        pw = env_passphrase(a.passphrase_env) if a.passphrase_env else None
        if not pw and not a.no_passphrase:
            instead = "pass --passphrase-env VARIABLE, or --no-passphrase"
            pw = ask("Passphrase for the new key: ", instead)
            if ask("Repeat: ", instead) != pw:
                raise VaultError("the passphrases do not match")
        ident.save(f"{a.out}.key", pw)
        Path(f"{a.out}.pub").write_bytes(ident.public.pem())
        print(f"{a.out}.key (keep secret) and {a.out}.pub (share with people who encrypt for you), id {ident.public.id}")
    elif a.vault_cmd in ("encrypt", "backup"):
        rec = [vault.Recipient.load(r) for r in a.recipient]
        if len({r.id for r in rec}) < 2:
            lone = (f"only one key can open this {'backup' if a.vault_cmd == 'backup' else 'file'}: lose it (or its passphrase) and the data is "
                    "gone for good. Add a recovery key kept offline, e.g. -r ops.pub -r recovery.pub")
            if a.vault_cmd == "backup" and not a.no_recovery_key:
                raise VaultError(f"{lone}; or pass --no-recovery-key to accept the risk")
            print(f"warning: {lone}", file=sys.stderr)
        if a.vault_cmd == "encrypt":
            if Path(a.out).exists():
                raise VaultError(f"{a.out} already exists; choose another -o")
            vault.encrypt(a.source, a.out, rec, signer())
            print(f"encrypted {a.source} -> {a.out} for {len(rec)} recipient(s)")
        else:
            target, pruned = vault.backup(a.source, a.to, rec, signer(), a.keep)
            print(f"backup {target}" + (f"; removed {len(pruned)} old" if pruned else ""))
    elif a.vault_cmd == "decrypt":
        target, who = vault.decrypt(a.file, a.out, vault.Identity.load(a.key, passphrase()), a.ca, a.crl, a.signer, a.require_signature)
        if not who:
            print(f"restored {target}; the file is not signed")
        elif a.ca:
            print(f"restored {target}, signed by {who} (certificate checked against {a.ca})")
        else:
            print(f"restored {target}; the signature is intact, but nobody checked who issued the signer's certificate "
                  f"({who}). Pass --ca to require one of your CA's certificates.")
    elif a.vault_cmd == "verify":
        r = vault.verify(a.file, vault.Identity.load(a.key, passphrase()), a.ca, a.crl, a.signer, a.require_signature)
        what = f"{r['files']} file(s), {r['bytes']} bytes" if r["kind"] == "dir" else f"{r['bytes']} bytes"
        print(f"{a.file}: restores {r['name']} ({what}); every chunk authenticated; opens for {r['recipients']} key(s); "
              + (f"signed by {r['signed_by']}" if r["signed_by"] else "not signed") + "; nothing was written")
        if r["signed_by"] and not a.ca:
            print("The signature is intact; the signer's certificate issuer was not checked. Pass --ca to require your CA.")
        if r["recipients"] < 2:
            print("warning: only one key opens it; `pqcsuite vault share` adds a recovery key without re-encrypting", file=sys.stderr)
    elif a.vault_cmd == "share":
        n = vault.add_recipients(a.file, vault.Identity.load(a.key, passphrase()), [vault.Recipient.load(r) for r in a.recipient])
        print(f"{a.file} now opens for {n} recipient(s); the encrypted data was not rewritten")
    elif a.vault_cmd == "inspect":
        show(vault.inspect(a.file), a.json)
        if not a.json:
            print("Header metadata only: integrity and the claimed signer are unverified. Use `vault verify` with a recipient key.")
    return 0


def cmd_bundle(a):
    from .tls.bundles import create
    out = create(a.service, a.out or f"{a.service}-pqc", a.host, a.ca, a.mtls, a.policy, ca_passphrase(a.ca) if a.ca else None)
    print((out / "README.txt").read_text())
    return 0


def cmd_project_scan(a):
    import webbrowser
    from .project import scan
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


def cmd_console(a):
    from .console import App, Settings, serve
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
        from .project import sample_project, scanner
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


def cmd_enroll(a):
    from .pki import est
    key_passphrase = env_passphrase(a.key_passphrase_env)
    if getattr(a, 'guide', False):
        if a.renew:
            raise CAError('--guide is for first enrollment; use --renew with an existing device folder')
        if not sys.stdin.isatty():
            raise CAError('--guide needs an interactive terminal; automation should supply enrollment flags and secret environment variables')
        from .checks import prerequisites
        failures = [r for r in prerequisites('tls') if r['level'] == 'fail']
        if failures:
            raise CAError(failures[0]['message'] + '. ' + failures[0]['action'])
        a.url = a.url or input('Enrollment service HTTPS URL: ').strip()
        a.common_name = a.common_name or input('Device or service name assigned by your administrator: ').strip()
        if not a.ca and not a.ca_fingerprint:
            a.ca_fingerprint = input('CA SHA-256 fingerprint supplied by your administrator: ').strip()
        a.token = a.token or os.environ.get('PQCSUITE_ENROLL_TOKEN') or getpass.getpass('One-time enrollment token: ')
        if not key_passphrase:
            key_passphrase = getpass.getpass('New local key passphrase: ').encode()
            if not key_passphrase or key_passphrase != getpass.getpass('Repeat key passphrase: ').encode():
                raise CAError('A nonempty matching passphrase is required for guided enrollment')
    if not a.url or not a.url.startswith('https://'):
        raise CAError('Supply an HTTPS enrollment URL, or use --guide')
    if a.renew:
        cert = est.renew(a.url, a.renew, within_days=a.within_days, passphrase=key_passphrase, server_name=a.server_name)
        print(f"{a.renew}: " + (f"renewed, new serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}" if cert
                                else f"still valid for more than {a.within_days} days, nothing to do"))
        return 0
    token = a.token or os.environ.get("PQCSUITE_ENROLL_TOKEN")
    if not (token and a.common_name):
        raise CAError("first enrollment needs the token (PQCSUITE_ENROLL_TOKEN, or --token) and --cn (renewal needs --renew FOLDER)")
    ca = a.ca
    if not ca:
        if not a.ca_fingerprint:
            raise CAError("give --ca FILE or --ca-fingerprint SHA256 (from `pqcsuite ca serve`) so the CA can be trusted")
        ca = Path(a.out) / "ca.crt"
        est.fetch_ca(a.url, a.ca_fingerprint, ca, a.server_name)
    cert = est.enroll(a.url, token, a.common_name, a.san, a.out, ca, passphrase=key_passphrase, server_name=a.server_name)
    print(f"enrolled {a.common_name}: serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}, files in {a.out}")
    print(f"renew it daily from cron: pqcsuite ca enroll {a.url} --renew {a.out} --within-days 30")
    return 0


def cmd_try(a):
    """A self-contained tour, nothing to set up: a CA, a plain web server, the post-quantum edge in front of it, a
    post-quantum client that gets through and a classical one that does not. Everything lives in a temporary folder."""
    import tempfile
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from .tls.edge import Edge, Route
    from .tls.openssl import Context
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


def cmd_report(a):
    from .readiness import compliance
    from .readiness import scan
    from .console import App, Settings
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


def positive(kind):
    def check(s):
        try:
            v = kind(s)
        except ValueError:
            v = 0
        if not v > 0:
            raise argparse.ArgumentTypeError(f"expected a number above 0, got {s!r}")
        return v
    return check


def run_until_signal(run, stop, reload=None):
    """Run until SIGINT or SIGTERM calls `stop`. With `reload`, SIGHUP (`systemctl reload`) calls it, where the platform has one."""
    def handle(*_):
        logging.getLogger(NAME).info("shutting down")
        stop()
    signal.signal(signal.SIGINT, handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle)
    if reload and hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: reload())
    run()


class JSONFormatter(logging.Formatter):
    def format(self, r):
        out = {"time": self.formatTime(r), "level": r.levelname, "logger": r.name, "message": r.getMessage()}
        if r.exc_info:
            out["exception"] = self.formatException(r.exc_info)
        return json.dumps(out)


# Help for options many commands share, filled in wherever a command gives none of its own
HELP = {
    "key_passphrase_env": "the key's passphrase is in this environment variable",
    "passphrase_env": "the key's passphrase is in this environment variable (otherwise you are asked)",
    "sign_key": "the signing certificate's private key",
    "sign_passphrase_env": "the signing key's passphrase is in this environment variable",
    "json": "print JSON instead of text",
    "timeout": "seconds to wait for each connection",
    "workers": "endpoints scanned at once",
    "vici": "strongSwan's control socket (default: unix:///var/run/charon.vici)",
    "interface": "the WireGuard interface (default: wg0)",
    "san": "another DNS name or IP address the certificate covers (repeatable)",
    "days": "certificate lifetime in days",
    "algorithm": "the key's algorithm",
    "out": "folder to write to",
    "file": "the Vault file (.pqv)",
    "source": "the file or folder to encrypt",
    "serial": "from `ca list`; the first 8 or more hex characters are enough",
    "kind": "server, client, or site (a VPN gateway: both)",
    "common_name": "the name it certifies, e.g. web.corp.example",
    "csr": "the certificate signing request (PEM)",
    "recipient": "a recipient's .pub file (repeatable)",
    "no_passphrase": "leave the private key unencrypted",
    "names": "the DNS names the certificate is for",
    "server_name": "the name in the server's certificate, if not its host",
    "html": "also write the report as a web page here",
    "backups": "a folder of Vault backups to include",
    "note": "a note to remember whom the key is for",
    "service": "the service to put behind the edge",
    "tls_key": "the --tls-cert private key",
    "ca": "the CA certificate to trust",
    "key": "the private key",
    "verbose": "log debugging detail",
}


def explain_options(p):
    for a in p._actions:
        if isinstance(a, argparse._SubParsersAction):
            for c in a.choices.values():
                explain_options(c)
        elif a.help is None and a.dest in HELP:
            a.help = HELP[a.dest]


def tls_client_args(p):
    p.add_argument("target", help="host:port")
    p.add_argument("--server-name", help="name the certificate must match (default: host)")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict", help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024 and ML-DSA-87 only")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Post-quantum products: TLS 1.3 + mTLS, VPN, Vault and Readiness assessment.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
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
    t = sub.add_parser("tls", help="TLS 1.3 + mTLS: post-quantum edge, server and client").add_subparsers(dest="tls_cmd", required=True)
    p = t.add_parser("edge", help="post-quantum TLS in front of any TCP service, or a tunnel to one")
    p.set_defaults(func=cmd_edge)
    p.add_argument("--config", help="TOML file with [[edge]] routes; replaces the flags below")
    p.add_argument("--mode", choices=["terminate", "originate"], default="terminate",
                   help="terminate: post-quantum TLS in front of --target; originate: plain local clients reach a remote edge at --target")
    p.add_argument("--listen", default="0.0.0.0:8443", help="host:port (default: every interface, port 8443)")
    p.add_argument("--target", help="upstream host:port (terminate) or remote edge host:port (originate)")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict", help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024 and ML-DSA-87 only")
    for flag, text in (("--cert", "the edge's certificate chain (chain.pem)"), ("--key", "its private key (key.pem)"),
                       ("--key-passphrase-env", "the key's passphrase is in this environment variable"),
                       ("--ca", "CA certificate that client certificates (terminate) or the remote edge (originate) must chain to"),
                       ("--crl", "refuse certificates revoked in this CRL file"),
                       ("--crl-url", "fetch the CRL from here every minute (from `ca publish`), into --crl"),
                       ("--server-name", "originate: the name in the remote edge's certificate, if not its host"),
                       ("--metrics", "host:port for /metrics (Prometheus), /healthz and /status, e.g. 127.0.0.1:9100")):
        p.add_argument(flag, help=text)
    p.add_argument("--fallback-cert", help="with --policy transition: an ECDSA or RSA certificate for browsers that cannot verify ML-DSA")
    p.add_argument("--fallback-key", help="the fallback certificate's private key")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--proxy-protocol", action="store_true", help="send a PROXY v1 header so the upstream sees the client address")
    p.add_argument("--workers", type=int, default=1, help="processes sharing the listen ports, e.g. one per CPU core (Linux)")
    from .tls.bundles import SERVICES
    p = t.add_parser("bundle", help="nginx, postgres, pgvector or mqtt behind the edge, with certificates and a compose file")
    p.set_defaults(func=cmd_bundle)
    p.add_argument("service", choices=list(SERVICES))
    p.add_argument("--host", required=True, help="the name clients use; goes in the certificate")
    p.add_argument("--out", help="folder to create (default: SERVICE-pqc)")
    p.add_argument("--ca", help="use this existing CA folder instead of creating one")
    p.add_argument("--mtls", action="store_true", help="clients must present a certificate from the CA")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict", help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024 and ML-DSA-87 only")
    p = t.add_parser("serve", help="an echo server, for testing clients")
    p.set_defaults(func=cmd_tls)
    p.add_argument("--listen", default="0.0.0.0:8443", help="host:port (default: every interface, port 8443)")
    p.add_argument("--cert", required=True, help="chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    p.add_argument("--ca", help="CA that signs client certificates")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--crl", help="refuse revoked client certificates")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict", help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024 and ML-DSA-87 only")
    p = t.add_parser("connect", help="handshake, optionally send a message, print what was negotiated")
    p.set_defaults(func=cmd_tls)
    tls_client_args(p)
    p.add_argument("--ca", required=True)
    p.add_argument("--cert", help="client certificate, for mutual TLS")
    p.add_argument("--key")
    p.add_argument("--key-passphrase-env")
    p.add_argument("--send", help="message to send; the reply is printed")

    ca = sub.add_parser("ca", help="TLS 1.3 + mTLS: the post-quantum certificate authority, EST and ACME").add_subparsers(dest="ca_cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default="pki", help="CA folder (default: pki)")
    p = ca.add_parser("init", parents=[common], help="create a root or intermediate CA",
                      epilog='example: pqcsuite ca init --name "Example Root CA" --dir pki')
    p.add_argument("--name", required=True, help="the CA's name, shown in every certificate it issues, e.g. \"Acme PQC Root\"")
    p.add_argument("--algorithm", choices=CA_ALGORITHMS, default="ML-DSA-87", help="SLH-DSA keys need OpenSSL 3.5+")
    p.add_argument("--parent", help="the CA folder that signs this one, making it an intermediate CA")
    p.add_argument("--kms", metavar="KEY_ID", help="keep the CA key in AWS KMS (an ML_DSA_* key); needs boto3")
    p.add_argument("--kms-region", help="the KMS key's AWS region (default: from your AWS configuration)")
    p.add_argument("--signer-command", nargs="+", metavar="ARG", help="an HSM tool that reads data on stdin and writes the signature")
    p.add_argument("--signer-public-key", help="PEM public key of the --signer-command key")
    p.add_argument("--days", type=int, default=3650, help="the CA certificate's lifetime (default: 3650, ten years)")
    enc = p.add_mutually_exclusive_group()
    enc.add_argument("--encrypt", action="store_true", help=argparse.SUPPRESS)  # the default now; still accepted from older scripts
    enc.add_argument("--no-encrypt", action="store_true",
                     help=f"leave the CA key unencrypted (by default it is encrypted, passphrase from {CA_PASS_ENV} or a prompt)")
    for name in ("issue", "renew"):
        p = ca.add_parser(name, parents=[common], help="issue a key and certificate" if name == "issue" else "new key and certificate, same names",
                          epilog="example: pqcsuite ca issue server web.corp.example --dir pki --out web" if name == "issue" else
                          "example: pqcsuite ca renew 3f9a1c2e7b --dir pki --out web (serials from `ca list`)")
        if name == "issue":
            p.add_argument("kind", choices=["server", "client", "site"], help="site: a VPN gateway (server and client)")
            p.add_argument("common_name", help="the name it certifies: a host name such as web.corp.example, or a person or device")
            p.add_argument("--san", action="append", default=[], help="DNS name or IP (repeatable; servers default to the common name)")
        else:
            p.add_argument("serial", help="from `ca list`; the first 8 or more hex characters are enough")
        p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65" if name == "issue" else None,
                       help=None if name == "issue" else "default: the algorithm of the certificate being renewed")
        p.add_argument("--days", type=int, default=397)
        p.add_argument("--out", help="folder for cert.pem, chain.pem and key.pem")
        p.add_argument("--key-passphrase-env", help="encrypt the new key with the passphrase in this environment variable")
    p = ca.add_parser("sign-csr", parents=[common], help="certify a key generated elsewhere")
    p.add_argument("csr")
    p.add_argument("--kind", choices=["server", "client", "site"], required=True)
    p.add_argument("--days", type=int, default=397)
    p.add_argument("--out", required=True, help="the certificate file to write")
    p = ca.add_parser("revoke", parents=[common], help="revoke a certificate and refresh the CRL")
    p.add_argument("serial")
    p.add_argument("--reason", default="unspecified", choices=["unspecified", *REASONS],
                   help="recorded in the CRL; keyCompromise when the key was stolen or exposed")
    p = ca.add_parser("crl", parents=[common], help="re-sign the CRL (do this before it expires)")
    p.add_argument("--days", type=positive(int), default=7, help="how long the CRL is valid (default: 7); re-sign it before then")
    p = ca.add_parser("maintain", parents=[common], help="renew what expires soon and refresh the CRL (run daily)")
    p.add_argument("--renew-within", type=int, default=30, metavar="DAYS", help="renew certificates expiring within DAYS (default: 30)")
    p.add_argument("--crl-days", type=positive(int), default=7, help="how long the re-signed CRL is valid (default: 7 days)")
    p = ca.add_parser("list", parents=[common], help="list issued certificates")
    p.add_argument("--expiring", type=int, metavar="DAYS", help="only those expiring within DAYS")
    p.add_argument("--json", action="store_true")
    p = ca.add_parser("token", parents=[common], help="one-time enrollment token for one name (for `ca enroll`)")
    p.add_argument("kind", choices=["server", "client", "site"])
    p.add_argument("common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--hours", type=positive(float), default=24, help="how long the token can be used (default: 24)")
    p = ca.add_parser("publish", parents=[common], help="serve crl.pem and ca.crt over HTTP, for edges and gateways to follow (crl_url)")
    p.add_argument("--listen", default="0.0.0.0:8080", help="host:port (default: every interface, port 8080)")
    p = ca.add_parser("serve", parents=[common], help="EST enrollment service (RFC 7030) over post-quantum TLS")
    p.add_argument("--listen", default="0.0.0.0:9443", help="host:port (default: every interface, port 9443)")
    p.add_argument("--cert", required=True, help="the service's own server chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    for c in ca.choices.values():
        c.set_defaults(func=cmd_ca)
    p = ca.add_parser("enroll", help="get or renew a certificate from an EST service; the key stays on this machine")
    p.set_defaults(func=cmd_enroll)
    p.add_argument("url", nargs="?", help="https://ca.example.com:9443")
    p.add_argument("--guide", action="store_true", help="interactive enrollment with pinned CA trust and an encrypted local key")
    p.add_argument("--token", help="one-time token from `ca token`; better in PQCSUITE_ENROLL_TOKEN, since other users can read command lines")
    p.add_argument("--cn", dest="common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--out", default=".")
    p.add_argument("--ca", help="trusted CA certificate")
    p.add_argument("--ca-fingerprint", help="or the CA's SHA-256 fingerprint, to download and pin it")
    p.add_argument("--renew", metavar="FOLDER", help="renew the certificate in FOLDER in place")
    p.add_argument("--within-days", type=int, help="with --renew: only when it expires within this many days")
    p.add_argument("--server-name")
    p.add_argument("--key-passphrase-env")
    p = ca.add_parser("acme", parents=[common], help="ACME (RFC 8555) service: ML-DSA certificates for clients that take a CSR (certbot --csr)")
    p.set_defaults(func=cmd_acme)
    p.add_argument("--listen", default="127.0.0.1:14000", help="host:port (default: this machine only, port 14000)")
    p.add_argument("--base-url", help="the URL clients use, e.g. https://acme.corp.example (default from --listen)")
    p.add_argument("--allow", action="append", default=[], help="names or patterns this CA issues for, e.g. '*.corp.example' (repeatable)")
    p.add_argument("--require-eab", action="store_true", help="clients need an external account binding key (see `ca eab`)")
    p.add_argument("--http-port", type=int, default=80, help="port for http-01 validation")
    p.add_argument("--allow-local-validation", action="store_true",
                   help="let http-01 validation reach loopback and link-local addresses (refused by default; private networks are allowed)")
    p.add_argument("--days", type=int, default=90, help="lifetime of issued certificates")
    p.add_argument("--tls-cert", help="a certificate ACME clients trust (classical: clients cannot verify ML-DSA yet)")
    p.add_argument("--tls-key")
    p = ca.add_parser("eab", parents=[common], help="an ACME external account binding key for one client")
    p.set_defaults(func=cmd_acme)
    p.add_argument("--note", default="")
    p = ca.add_parser("csr", help="an ML-DSA key and CSR, for certbot --csr")
    p.set_defaults(func=cmd_acme)
    p.add_argument("names", nargs="+")
    p.add_argument("--out", default=".")
    p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65")
    p.add_argument("--key-passphrase-env")

    v = sub.add_parser("vpn", help="VPN: post-quantum site-to-site IPsec (strongSwan), and remote access for laptops (WireGuard, the Acxelin VPN app)").add_subparsers(dest="vpn_cmd", required=True)
    p = v.add_parser("up", help="run a site: key agreement, rotation, revocation, metrics")
    p.add_argument("--config", required=True, help="site TOML (see examples/vpn-hq.toml)")
    for name, text in (("status", "is this machine protected? (laptop) or tunnels, algorithms and traffic (site)"),
                       ("check", "is strongSwan reachable and does it have ML-KEM?")):
        p = v.add_parser(name, help=text)
        p.add_argument("--config", help="read the VICI address from a site TOML")
        p.add_argument("--vici", help="strongSwan control socket (default unix:///var/run/charon.vici)")
        p.add_argument("--json", action="store_true")
        if name == "status":
            p.add_argument("--interface", default="wg0", help="the laptop tunnel to report on (default: wg0)")
            p.add_argument("--details", action="store_true", help="also show algorithms, handshake and key timing")
    p = v.add_parser("invite", parents=[common], help="administrator: one file that lets a person enroll and connect with `vpn join`")
    p.add_argument("name", help="the person's or device's certificate name (also add it to the gateway's users list, if it has one)")
    p.add_argument("--enroll", required=True, metavar="URL", help="the EST enrollment service, https://host:9443 (see `ca serve`)")
    p.add_argument("--gateway", required=True, metavar="HOST:PORT", help="the WireGuard gateway's key agreement address")
    p.add_argument("--server-name", help="the gateway's certificate name, if it differs from HOST")
    p.add_argument("--hours", type=positive(float), default=24, help="how long the invitation can be used (default: 24)")
    p.add_argument("--out", help="the invitation file (default: NAME.pqcinvite)")
    p = v.add_parser("join", help="enroll this machine from an invitation file and connect it, in one step")
    p.add_argument("invitation", help="the .pqcinvite file from your administrator")
    p.add_argument("--device", help="folder for this machine's certificate and key (default: next to the invitation, named after it)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--key-passphrase-env", help="read the device key passphrase from this environment variable instead of asking")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("app", help="a window in the browser to join, connect, disconnect and see whether this machine is protected")
    p.add_argument("invitation", nargs="?", help="the .pqcinvite file (default: the newest in ~/.pqcsuite/vpn; the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")
    p.add_argument("--folder", help="where invitations and this computer's keys are kept (default: ~/.pqcsuite/vpn)")
    p.add_argument("--session", help=argparse.SUPPRESS)
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p = v.add_parser("desktop", help="the desktop app: a tray icon that shows whether this computer is protected, and the VPN window")
    p.add_argument("invitation", nargs="?", help="the .pqcinvite file (the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--launcher", action="store_true", help="add Acxelin VPN to the Start menu, Applications or the application list")
    p.add_argument("--remove-launcher", action="store_true", help="remove what --launcher added")
    p.add_argument("--start-at-login", choices=("on", "off"), help="show the tray icon when you log in (it connects only when you ask)")
    p.add_argument("--background", action="store_true", help="start in the tray without opening the window")
    p = v.add_parser("gateway", help="WireGuard remote-access gateway: address pool, PSK from ML-DSA mutual TLS, rotation, revocation")
    p.add_argument("--config", required=True, help="TOML with a [wireguard] section (see examples/wireguard-gateway.toml)")
    for name, text in (("connect", "connect this machine (Linux, Windows or macOS) to a WireGuard gateway and keep its PSK fresh"),
                       ("install", "check gateway access and install a service that connects at machine startup")):
        p = v.add_parser(name, help=text)
        p.add_argument("keyring", help="the gateway's key agreement address, host:port")
        p.add_argument("--cert-dir", required=True, help="folder with cert.pem, chain.pem, key.pem and ca.crt (as written by `ca enroll`)")
        p.add_argument("--ca", help="trust this CA file instead of CERT_DIR/ca.crt")
        p.add_argument("--interface", default="wg0")
        p.add_argument("--server-name", help="the gateway's certificate name, if it differs from the keyring host")
        if name == "connect":
            p.add_argument("--no-apply", action="store_true", help="do not configure the tunnel (use with --config-out)")
            p.add_argument("--config-out", help="also write a wg-quick configuration here after every key agreement")
            p.add_argument("--key-passphrase-env")
            p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("disconnect", help="take the tunnel down and lift the kill switch")
    p.add_argument("--interface", default="wg0")
    v.add_parser("uninstall", help="stop starting the VPN with this machine")
    for c in v.choices.values():
        c.set_defaults(func=cmd_vpn)

    q = sub.add_parser("vault", help="Vault: quantum-safe encryption for files, folders and backups").add_subparsers(dest="vault_cmd", required=True)
    p = q.add_parser("keygen", help="a recipient key pair (ML-KEM-768 + X25519)")
    p.add_argument("out", help="writes OUT.key and OUT.pub")
    p.add_argument("--passphrase-env")
    p.add_argument("--no-passphrase", action="store_true")
    p.add_argument("--cnsa2", action="store_true", help="ML-KEM-1024 + P-384 (NSA CNSA 2.0) instead of ML-KEM-768 + X25519")
    for name in ("encrypt", "backup"):
        p = q.add_parser(name, help="encrypt a file or folder" if name == "encrypt" else "timestamped encrypted archive, with retention")
        p.add_argument("source")
        if name == "encrypt":
            p.add_argument("-o", "--out", required=True, help="the encrypted file to write, e.g. report.pdf.pqv")
        else:
            p.add_argument("--to", required=True, help="folder that holds the archives (sync it to any storage)")
            p.add_argument("--keep", type=int, help="keep only the newest N archives")
            p.add_argument("--no-recovery-key", action="store_true", help="allow a backup that a single key opens (losing it loses the data)")
        p.add_argument("-r", "--recipient", action="append", required=True, help="recipient .pub (repeatable)")
        p.add_argument("--sign-cert", help="sign with this CA-issued ML-DSA certificate")
        p.add_argument("--sign-key")
        p.add_argument("--sign-passphrase-env")
    for name, text in (("decrypt", "decrypt and verify"), ("verify", "restore drill: prove an archive opens with this key and is intact, writing nothing")):
        p = q.add_parser(name, help=text)
        p.add_argument("file")
        p.add_argument("-k", "--key", required=True, help="your .key file")
        if name == "decrypt":
            p.add_argument("-o", "--out", default=".", metavar="FOLDER",
                           help="folder to restore into (default: this one); the original file or folder name is kept inside it")
        p.add_argument("--passphrase-env", metavar="VAR", help="the key's passphrase is in this environment variable (otherwise you are asked)")
        p.add_argument("--ca", help="the signer's certificate must chain to this CA")
        p.add_argument("--crl", help="and must not be revoked")
        p.add_argument("--signer", help="and must have this common name")
        p.add_argument("--require-signature", action="store_true", help="refuse a file that is not signed")
    p = q.add_parser("share", help="let more recipients open a file, without re-encrypting it")
    p.add_argument("file")
    p.add_argument("-k", "--key", required=True, help="your .key file (you must be able to open the file)")
    p.add_argument("-r", "--recipient", action="append", required=True)
    p.add_argument("--passphrase-env")
    p = q.add_parser("inspect", help="who can open a file and who signed it")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    for c in q.choices.values():
        c.set_defaults(func=cmd_vault)

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
    explain_options(ap)
    return ap


def main(argv=None):
    ap = parser()
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        print(f"\nNew here? `{NAME} try` runs a one-minute tour; `{NAME} doctor` checks this machine.")
        sys.exit(0)
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter() if a.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, handlers=[h])
    try:
        sys.exit(a.func(a))
    except BrokenPipeError:  # output piped into head, or a pager closed early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    except (CAError, CharonError, WGError, VaultError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {explain(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
