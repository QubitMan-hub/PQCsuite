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

from . import HTTP_IDLE, NAME, __version__, explain, tls
from .pki import ALGORITHMS, CA, CA_ALGORITHMS, CAError, encrypted
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
    p1, p2 = ask("New CA passphrase: ", f"set {CA_PASS_ENV}"), ask("Repeat: ", f"set {CA_PASS_ENV}")
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1


def env_passphrase(var):
    if not var:
        return None
    if var not in os.environ:
        raise CAError(f"environment variable {var} is not set")
    return os.environ[var].encode()


def show(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=1, default=str))
    else:
        for k, v in obj.items():
            print(f"{k:>14}  {v}")


def cmd_doctor(a):
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    print(f"{NAME} {__version__}, Python {sys.version.split()[0]}")
    print(f"cryptography {cryptography.__version__} with {backend.openssl_version_text()}: certificate authority ready")
    try:
        lib = tls.lib()
        ctx = tls.client_context(verify=False)
        ctx.close()
        print(f"TLS: {lib.version}, groups {tls.PQC_GROUPS} available")
        return 0
    except tls.TLSError as e:
        print(f"TLS: not available: {e}")
        return 1


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
        ca = CA.init(a.dir, a.name, a.algorithm, a.days, ca_passphrase(a.dir, new=True) if a.encrypt and not signer else None, parent, signer)
        what = f"intermediate CA under '{parent.cert.subject.rfc4514_string()}'" if parent else "root"
        print(f"created {ca.algorithm} {what} '{a.name}' in {a.dir} (serial {ca.cert.serial_number:x}); clients trust {ca.anchor}, servers check {Path(a.dir) / 'crl.pem'}")
        return 0
    ca = CA(a.dir, None if a.ca_cmd == "list" else ca_passphrase(a.dir))
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
        print(f"revoked {ca.find(a.serial).serial}; {Path(a.dir) / 'crl.pem'} updated, distribute it to your servers")
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

        srv = Server(parse_addr(a.listen), make, echo, watch=[a.cert, a.key, a.ca], crl=a.crl, ca=a.ca, name="serve")
        run_until_signal(srv.serve_forever, srv.stop)
        return 0
    host, port = parse_addr(a.target, "")
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
    s = scan.summary(results)
    print(f"\n{s['pq_key_exchange']}/{s['endpoints']} offer post-quantum key exchange; {s['pq_certificates']} use ML-DSA certificates")
    return 0 if s["pq_key_exchange"] == s["endpoints"] else 2


def cmd_edge(a):
    from .tls.edge import WORKER, Edge, Route, Workers, load_config, report, serve_metrics
    if not (a.config or a.target):
        raise ValueError("edge needs --config or --target")
    if a.config:
        routes, metrics = load_config(a.config)
    else:
        routes = [Route(name="edge", mode=a.mode, listen=a.listen, target=a.target, policy=a.policy, cert=a.cert or "", key=a.key or "",
                        key_passphrase_env=a.key_passphrase_env or "", ca=a.ca or "", require_client_cert=a.require_client_cert,
                        crl=a.crl or "", server_name=a.server_name or "", proxy_protocol=a.proxy_protocol,
                        fallback_cert=a.fallback_cert or "", fallback_key=a.fallback_key or "")]
        metrics = a.metrics
    if a.workers < 1:
        raise ValueError("--workers must be 1 or more")
    worker = bool(os.environ.get(WORKER))
    shared = a.workers > 1 or worker
    if shared:
        if any(parse_addr(r.listen)[1] == 0 for r in routes):
            raise ValueError("--workers needs a fixed listen port, not 0")
        if not sys.platform.startswith("linux"):
            raise ValueError("--workers needs Linux, where the kernel spreads connections over the processes (SO_REUSEPORT)")
    edges = [Edge(r).bind(reuse_port=shared) for r in routes]
    workers = Workers(a.workers) if a.workers > 1 and not worker else None
    if worker:
        threading.Thread(target=report, args=(edges,), daemon=True).start()
    elif metrics:
        serve_metrics(metrics, edges, workers)
    threads = [threading.Thread(target=e.serve_forever, daemon=True, name=e.route.name) for e in edges]
    for t in threads:
        t.start()

    def stop():
        for e in edges:
            e.stop()
        if workers:
            workers.stop()
    run_until_signal(lambda: [t.join() for t in threads], stop)
    return 0


def cmd_vpn(a):
    from .vpn import load_config
    from .vpn.charon import Charon
    if a.vpn_cmd in ("gateway", "connect"):
        return cmd_wireguard(a)
    if a.vpn_cmd == "up":
        from .vpn.controller import Controller
        site = load_config(a.config)
        ctl = Controller(site)
        ctl.start()
        if site.metrics:
            serve_json(site.metrics, {"/metrics": ctl.metrics, "/status": lambda: json.dumps(ctl.status(), default=str)})
        run_until_signal(lambda: ctl.stop.wait(), ctl.shutdown)
        return 0
    ch = Charon(load_config(a.config).vici if a.config else a.vici)
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


def cmd_wireguard(a):
    from .vpn import wireguard as wg
    if a.vpn_cmd == "gateway":
        gw = wg.Gateway(wg.load_gateway(a.config)).start()
        print(f"WireGuard gateway {gw.cfg.name} on {gw.cfg.interface}, key agreement on {gw.cfg.keyring_listen}, public key {gw.public}")
        if gw.cfg.metrics:
            serve_json(gw.cfg.metrics, {"/metrics": gw.metrics, "/status": lambda: json.dumps(gw.status(), default=str)})
        run_until_signal(lambda: gw.stop.wait(), gw.shutdown)
        return 0
    c = wg.Client(a.keyring, a.cert_dir, a.interface, a.server_name, not a.no_apply, a.config_out, env_passphrase(a.key_passphrase_env), ca=a.ca)
    if a.once:
        r = c.once()
        print(f"connected as {r['address']} through {r['endpoint']}; routes {', '.join(r['routes'])}; the PSK expires in about {r['rotate_s'] * 3}s")
        return 0
    run_until_signal(c.run, c.stop.set)
    return 0


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
    httpd = acme.serve(acme.Service(ca, base, a.allow, a.require_eab, a.http_port, days=a.days), a.listen, a.tls_cert, a.tls_key)
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
    elif a.vault_cmd == "share":
        n = vault.add_recipients(a.file, vault.Identity.load(a.key, passphrase()), [vault.Recipient.load(r) for r in a.recipient])
        print(f"{a.file} now opens for {n} recipient(s); the encrypted data was not rewritten")
    elif a.vault_cmd == "inspect":
        show(vault.inspect(a.file), a.json)
    return 0


def cmd_bundle(a):
    from .tls.bundles import create
    out = create(a.service, a.out or f"{a.service}-pqc", a.host, a.ca, a.mtls, a.policy, ca_passphrase(a.ca) if a.ca else None)
    print((out / "README.txt").read_text())
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
    if s.ca and not (Path(s.ca) / "ca.crt").exists():
        raise ValueError(f"no CA at {s.ca}; run 'pqcsuite ca init' first, or leave out --ca")
    app = App(s)
    httpd = serve(app)
    host, port = httpd.server_address[:2]
    print(f"console on http://{host}:{port}/  access token: {app.token}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print("warning: listening beyond localhost over plain HTTP; put `pqcsuite tls edge --policy transition` in front of it")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    stop = threading.Event()
    run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    return 0


def cmd_enroll(a):
    from .pki import est
    if a.renew:
        cert = est.renew(a.url, a.renew, within_days=a.within_days, passphrase=env_passphrase(a.key_passphrase_env), server_name=a.server_name)
        print(f"{a.renew}: " + (f"renewed, new serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}" if cert
                                else f"still valid for more than {a.within_days} days, nothing to do"))
        return 0
    if not (a.token and a.common_name):
        raise CAError("first enrollment needs --token and --cn (renewal needs --renew FOLDER)")
    ca = a.ca
    if not ca:
        if not a.ca_fingerprint:
            raise CAError("give --ca FILE or --ca-fingerprint SHA256 (from `pqcsuite ca serve`) so the CA can be trusted")
        ca = Path(a.out) / "ca.crt"
        est.fetch_ca(a.url, a.ca_fingerprint, ca, a.server_name)
    cert = est.enroll(a.url, a.token, a.common_name, a.san, a.out, ca, passphrase=env_passphrase(a.key_passphrase_env), server_name=a.server_name)
    print(f"enrolled {a.common_name}: serial {cert.serial_number:x}, valid until {cert.not_valid_after_utc.date()}, files in {a.out}")
    print(f"renew it daily from cron: pqcsuite ca enroll {a.url} --renew {a.out} --within-days 30")
    return 0


def cmd_report(a):
    from .readiness import compliance
    from .readiness import scan
    from .console import App, Settings
    if not (a.ca or a.targets or a.vici or a.backups):
        raise ValueError("nothing to report on: pass --ca, --targets, --vici or --backups")
    app = App(Settings(ca=a.ca or "", vpn=a.vici, backups=a.backups))
    rows = []
    if a.ca:
        rows += compliance.certificates(app.ca().records())
    targets = scan.load_targets(a.targets)
    if targets:
        rows += compliance.endpoints(scan.scan(targets, timeout=a.timeout))
    rows += compliance.tunnels(app.tunnels()) + compliance.backups(app.backups())
    rep = compliance.report(rows)
    if a.html:
        Path(a.html).write_text(compliance.to_html(rep), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(compliance.to_json(rep), encoding="utf-8")
    s = rep["status"]
    print(f"{rep['assets']} assets: {s['ready']} quantum-safe, {s['transition']} with classical fallback, {s['action']} need action; "
          f"{rep['cnsa2_compliant']} meet CNSA 2.0")
    return 0 if not s["action"] else 2


def serve_json(address, routes):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE

        def do_GET(self):
            fn = routes.get(self.path) or (lambda: "ok\n" if self.path == "/healthz" else None)
            body = fn()
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(parse_addr(address, "127.0.0.1"), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def parse_addr(s, default_host="0.0.0.0"):
    from .tls import hostport
    return hostport(s, default_host)


def run_until_signal(run, stop):
    def handle(*_):
        logging.getLogger(NAME).info("shutting down")
        stop()
    signal.signal(signal.SIGINT, handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle)
    run()


class JSONFormatter(logging.Formatter):
    def format(self, r):
        out = {"time": self.formatTime(r), "level": r.levelname, "logger": r.name, "message": r.getMessage()}
        if r.exc_info:
            out["exception"] = self.formatException(r.exc_info)
        return json.dumps(out)


def tls_client_args(p):
    p.add_argument("target", help="host:port")
    p.add_argument("--server-name", help="name the certificate must match (default: host)")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Post-quantum products: TLS 1.3 + mTLS, IPsec VPN, Vault and Readiness assessment.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check that this machine can run everything").set_defaults(func=cmd_doctor)

    t = sub.add_parser("tls", help="TLS 1.3 + mTLS: post-quantum edge, server and client").add_subparsers(dest="tls_cmd", required=True)
    p = t.add_parser("edge", help="post-quantum TLS in front of any TCP service, or a tunnel to one")
    p.set_defaults(func=cmd_edge)
    p.add_argument("--config", help="TOML file with [[edge]] routes; replaces the flags below")
    p.add_argument("--mode", choices=["terminate", "originate"], default="terminate")
    p.add_argument("--listen", default="0.0.0.0:8443")
    p.add_argument("--target", help="upstream host:port (terminate) or remote edge host:port (originate)")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    for flag in ("--cert", "--key", "--key-passphrase-env", "--ca", "--crl", "--server-name", "--metrics"):
        p.add_argument(flag)
    p.add_argument("--fallback-cert", help="with --policy transition: an ECDSA or RSA certificate for browsers that cannot verify ML-DSA")
    p.add_argument("--fallback-key")
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
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    p = t.add_parser("serve", help="an echo server, for testing clients")
    p.set_defaults(func=cmd_tls)
    p.add_argument("--listen", default="0.0.0.0:8443")
    p.add_argument("--cert", required=True, help="chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    p.add_argument("--ca", help="CA that signs client certificates")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--crl", help="refuse revoked client certificates")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
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
    p = ca.add_parser("init", parents=[common], help="create a root or intermediate CA")
    p.add_argument("--name", required=True)
    p.add_argument("--algorithm", choices=CA_ALGORITHMS, default="ML-DSA-87", help="SLH-DSA keys need OpenSSL 3.5+")
    p.add_argument("--parent", help="the CA folder that signs this one, making it an intermediate CA")
    p.add_argument("--kms", metavar="KEY_ID", help="keep the CA key in AWS KMS (an ML_DSA_* key); needs boto3")
    p.add_argument("--kms-region")
    p.add_argument("--signer-command", nargs="+", metavar="ARG", help="an HSM tool that reads data on stdin and writes the signature")
    p.add_argument("--signer-public-key", help="PEM public key of the --signer-command key")
    p.add_argument("--days", type=int, default=3650)
    p.add_argument("--encrypt", action="store_true", help=f"encrypt the CA key (passphrase from {CA_PASS_ENV} or a prompt)")
    for name in ("issue", "renew"):
        p = ca.add_parser(name, parents=[common], help="issue a key and certificate" if name == "issue" else "new key and certificate, same names")
        if name == "issue":
            p.add_argument("kind", choices=["server", "client", "site"], help="site: a VPN gateway (server and client)")
            p.add_argument("common_name")
            p.add_argument("--san", action="append", default=[], help="DNS name or IP (repeatable; servers default to the common name)")
        else:
            p.add_argument("serial")
        p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65" if name == "issue" else None,
                       help=None if name == "issue" else "default: the algorithm of the certificate being renewed")
        p.add_argument("--days", type=int, default=397)
        p.add_argument("--out", help="folder for cert.pem, chain.pem and key.pem")
        p.add_argument("--key-passphrase-env", help="encrypt the new key with the passphrase in this environment variable")
    p = ca.add_parser("sign-csr", parents=[common], help="certify a key generated elsewhere")
    p.add_argument("csr")
    p.add_argument("--kind", choices=["server", "client", "site"], required=True)
    p.add_argument("--days", type=int, default=397)
    p.add_argument("--out", required=True)
    p = ca.add_parser("revoke", parents=[common], help="revoke a certificate and refresh the CRL")
    p.add_argument("serial")
    p.add_argument("--reason", default="unspecified")
    p = ca.add_parser("crl", parents=[common], help="re-sign the CRL (do this before it expires)")
    p.add_argument("--days", type=int, default=7)
    p = ca.add_parser("maintain", parents=[common], help="renew what expires soon and refresh the CRL (run daily)")
    p.add_argument("--renew-within", type=int, default=30, metavar="DAYS")
    p.add_argument("--crl-days", type=int, default=7)
    p = ca.add_parser("list", parents=[common], help="list issued certificates")
    p.add_argument("--expiring", type=int, metavar="DAYS", help="only those expiring within DAYS")
    p.add_argument("--json", action="store_true")
    p = ca.add_parser("token", parents=[common], help="one-time enrollment token for one name (for `ca enroll`)")
    p.add_argument("kind", choices=["server", "client", "site"])
    p.add_argument("common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--hours", type=float, default=24)
    p = ca.add_parser("serve", parents=[common], help="EST enrollment service (RFC 7030) over post-quantum TLS")
    p.add_argument("--listen", default="0.0.0.0:9443")
    p.add_argument("--cert", required=True, help="the service's own server chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    for c in ca.choices.values():
        c.set_defaults(func=cmd_ca)
    p = ca.add_parser("enroll", help="get or renew a certificate from an EST service; the key stays on this machine")
    p.set_defaults(func=cmd_enroll)
    p.add_argument("url", help="https://ca.example.com:9443")
    p.add_argument("--token", help="one-time token from `ca token`")
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
    p.add_argument("--listen", default="127.0.0.1:14000")
    p.add_argument("--base-url", help="the URL clients use, e.g. https://acme.corp.example (default from --listen)")
    p.add_argument("--allow", action="append", default=[], help="names or patterns this CA issues for, e.g. '*.corp.example' (repeatable)")
    p.add_argument("--require-eab", action="store_true", help="clients need an external account binding key (see `ca eab`)")
    p.add_argument("--http-port", type=int, default=80, help="port for http-01 validation")
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

    v = sub.add_parser("vpn", help="IPsec VPN: post-quantum site-to-site (strongSwan) and WireGuard remote access").add_subparsers(dest="vpn_cmd", required=True)
    p = v.add_parser("up", help="run a site: key agreement, rotation, revocation, metrics")
    p.add_argument("--config", required=True, help="site TOML (see examples/vpn-hq.toml)")
    for name, text in (("status", "tunnels, algorithms and traffic"), ("check", "is strongSwan reachable and does it have ML-KEM?")):
        p = v.add_parser(name, help=text)
        p.add_argument("--config", help="read the VICI address from a site TOML")
        p.add_argument("--vici", default="unix:///var/run/charon.vici")
        p.add_argument("--json", action="store_true")
    p = v.add_parser("gateway", help="WireGuard remote-access gateway: address pool, PSK from ML-DSA mutual TLS, rotation, revocation")
    p.add_argument("--config", required=True, help="TOML with a [wireguard] section (see examples/wireguard-gateway.toml)")
    p = v.add_parser("connect", help="connect this machine to a WireGuard gateway and keep its PSK fresh")
    p.add_argument("keyring", help="the gateway's key agreement address, host:port")
    p.add_argument("--cert-dir", required=True, help="folder with cert.pem, chain.pem, key.pem and ca.crt (as written by `ca enroll`)")
    p.add_argument("--ca", help="trust this CA file instead of CERT_DIR/ca.crt")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--server-name", help="the gateway's certificate name, if it differs from the keyring host")
    p.add_argument("--no-apply", action="store_true", help="do not configure the interface (use with --config-out)")
    p.add_argument("--config-out", help="also write a wg-quick configuration here after every key agreement")
    p.add_argument("--key-passphrase-env")
    p.add_argument("--once", action="store_true", help="agree once and exit")
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
            p.add_argument("-o", "--out", required=True)
        else:
            p.add_argument("--to", required=True, help="folder that holds the archives (sync it to any storage)")
            p.add_argument("--keep", type=int, help="keep only the newest N archives")
        p.add_argument("-r", "--recipient", action="append", required=True, help="recipient .pub (repeatable)")
        p.add_argument("--sign-cert", help="sign with this CA-issued ML-DSA certificate")
        p.add_argument("--sign-key")
        p.add_argument("--sign-passphrase-env")
    p = q.add_parser("decrypt", help="decrypt and verify")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("-o", "--out", default=".", help="folder to restore into; the original file or folder name is kept")
    p.add_argument("--passphrase-env")
    p.add_argument("--ca", help="the signer's certificate must chain to this CA")
    p.add_argument("--crl", help="and must not be revoked")
    p.add_argument("--signer", help="and must have this common name")
    p.add_argument("--require-signature", action="store_true")
    p = q.add_parser("share", help="let more recipients open a file, without re-encrypting it")
    p.add_argument("file")
    p.add_argument("--key", required=True, help="your key (you must be able to open the file)")
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
    p.add_argument("--html")
    p.add_argument("--json")
    p.add_argument("--timeout", type=float, default=8.0)

    p = sub.add_parser("console", help="one dashboard for all four products")
    p.set_defaults(func=cmd_console)
    p.add_argument("--config", help="TOML with a [console] section")
    p.add_argument("--listen", help="default 127.0.0.1:8900")
    p.add_argument("--ca", help="CA folder")
    p.add_argument("--edge", action="append", default=[], help="an edge's metrics address, e.g. http://127.0.0.1:9100 (repeatable)")
    p.add_argument("--vici", action="append", default=[], help="strongSwan VICI address (repeatable)")
    p.add_argument("--wireguard", action="append", default=[], help="a WireGuard gateway's metrics address (repeatable)")
    p.add_argument("--backups", action="append", default=[], help="folder of vault archives (repeatable)")
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter() if a.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, handlers=[h])
    try:
        sys.exit(a.func(a))
    except (CAError, CharonError, WGError, VaultError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {explain(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
