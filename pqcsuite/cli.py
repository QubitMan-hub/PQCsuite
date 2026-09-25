import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from . import NAME, __version__, tls
from .ca import ALGORITHMS, CA, CAError
from .vault import VaultError
from .vpn.charon import CharonError

CA_PASS_ENV = "PQCSUITE_CA_PASSPHRASE"


def ca_passphrase(root, new=False):
    """From PQCSUITE_CA_PASSPHRASE or a prompt, and only when the CA key is (or will be) encrypted."""
    key = Path(root) / "ca.key"
    if not new and not (key.exists() and b"ENCRYPTED" in key.read_bytes()[:64]):
        return None
    if os.environ.get(CA_PASS_ENV):
        return os.environ[CA_PASS_ENV].encode()
    if not new:
        return getpass.getpass("CA passphrase: ").encode()
    p1, p2 = getpass.getpass("New CA passphrase: "), getpass.getpass("Repeat: ")
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1.encode()


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
        ca = CA.init(a.dir, a.name, a.algorithm, a.days, ca_passphrase(a.dir, new=True) if a.encrypt else None)
        print(f"created {a.algorithm} root '{a.name}' in {a.dir} (serial {ca.cert.serial_number:x})")
        return 0
    ca = CA(a.dir, ca_passphrase(a.dir))
    if a.ca_cmd == "issue":
        out, r = ca.issue(a.common_name, a.kind, a.san, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"issued {r.kind} certificate {r.serial} for {r.common_name} ({r.algorithm}), valid until {r.not_after}")
        print(f"  {out / 'cert.pem'}\n  {out / 'chain.pem'}  (certificate + CA, use this for servers)\n  {out / 'key.pem'}")
    elif a.ca_cmd == "sign-csr":
        cert, r = ca.sign_csr(Path(a.csr).read_bytes(), a.kind, a.days)
        from .ca import cert_pem
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
        from .est import create_token
        t = create_token(ca, a.common_name, a.kind, a.san, a.hours)
        print(f"one-time enrollment token for {a.common_name} ({a.kind}), valid {a.hours} h. It is shown only once:\n{t}")
    elif a.ca_cmd == "serve":
        from .est import fingerprint, serve
        srv = serve(a.dir, a.listen, a.cert, a.key, ca_passphrase(a.dir), env_passphrase(a.key_passphrase_env))
        print(f"EST enrollment on https://{a.listen}/.well-known/est; CA fingerprint (give it to clients):\n{fingerprint(ca.cert)}")
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
    if a.tls_cmd == "probe":
        from .scan import GRADES, probe
        r = probe(a.target, a.server_name, a.timeout)
        r["verdict"] = f"{r['grade']}: {GRADES[r['grade']]}"
        show(r, a.json)
        return 0 if r["grade"] in "AB" else 2
    ctx = tls.client_context(a.ca, a.cert, a.key, a.policy, env_passphrase(a.key_passphrase_env))
    with tls.connect(host, port, ctx, a.server_name, a.timeout) as conn:
        out = conn.info()
        if a.send is not None:
            try:
                conn.sendall(a.send.encode())
                reply = conn.recv()
            except (tls.TLSError, OSError) as e:
                reply, out["error"] = b"", str(e)
            if not reply:
                raise tls.TLSError("the server closed the connection after the handshake: it probably refused our client certificate "
                                   f"(missing, untrusted or revoked){': ' + out['error'] if 'error' in out else ''}")
            out["reply"] = reply.decode(errors="replace")
    show(out, a.json)
    return 0


def cmd_scan(a):
    from . import scan
    results = scan.scan(scan.load_targets(a.targets), a.workers, a.timeout)
    if a.html:
        Path(a.html).write_text(scan.report_html(results), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(scan.to_json(results), encoding="utf-8")
    for r in sorted(results, key=lambda r: (r["grade"], r["target"])):
        cert = r["certificate"] or {}
        print(f"{r['grade']}  {r['target']:32} {r['negotiated'] or r['error'] or '':24} {cert.get('key', ''):14} {cert.get('expires', '')}")
    s = scan.summary(results)
    print(f"\n{s['pq_key_exchange']}/{s['endpoints']} offer post-quantum key exchange; {s['pq_certificates']} use ML-DSA certificates")
    return 0 if s["pq_key_exchange"] == s["endpoints"] else 2


def cmd_edge(a):
    from .edge import Edge, Route, load_config, serve_metrics
    if a.config:
        routes, metrics = load_config(a.config)
    else:
        routes = [Route(name="edge", mode=a.mode, listen=a.listen, target=a.target, policy=a.policy, cert=a.cert or "", key=a.key or "",
                        key_passphrase_env=a.key_passphrase_env or "", ca=a.ca or "", require_client_cert=a.require_client_cert,
                        crl=a.crl or "", server_name=a.server_name or "", proxy_protocol=a.proxy_protocol)]
        metrics = a.metrics
    edges = [Edge(r) for r in routes]
    if metrics:
        serve_metrics(metrics, edges)
    threads = [threading.Thread(target=e.serve_forever, daemon=True, name=e.route.name) for e in edges]
    for t in threads:
        t.start()
    run_until_signal(lambda: [t.join() for t in threads], lambda: [e.stop() for e in edges])
    return 0


def cmd_vpn(a):
    from .vpn import load_config
    from .vpn.charon import Charon
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
    for t in [] if a.json else tunnels:
        print(f"{t['peer']:16} {t['state']:12} {t['key_exchange']:32} PPK {'yes' if t['ppk'] else 'NO '}  up {t['established_s']}s")
        for c in t["children"]:
            print(f"  {c['name']:14} {c['state']:12} {c['encryption']:14} in {c['bytes_in']} B / out {c['bytes_out']} B")
    return 0


def cmd_vault(a):
    from . import vault
    def passphrase():
        if a.passphrase_env:
            return env_passphrase(a.passphrase_env)
        return getpass.getpass("Key passphrase: ").encode() if b"ENCRYPTED" in Path(a.key).read_bytes()[:64] else None

    signer = lambda: vault.load_signer(a.sign_cert, a.sign_key, env_passphrase(a.sign_passphrase_env)) if a.sign_cert else None
    if a.vault_cmd == "keygen":
        ident = vault.Identity.generate()
        pw = env_passphrase(a.passphrase_env) if a.passphrase_env else None
        if not pw and not a.no_passphrase:
            pw = getpass.getpass("Passphrase for the new key: ").encode()
            if getpass.getpass("Repeat: ").encode() != pw:
                raise VaultError("the passphrases do not match")
        ident.save(f"{a.out}.key", pw)
        Path(f"{a.out}.pub").write_bytes(ident.public.pem())
        print(f"{a.out}.key (keep secret) and {a.out}.pub (share with people who encrypt for you), id {ident.public.id}")
    elif a.vault_cmd in ("encrypt", "backup"):
        rec = [vault.Recipient.load(r) for r in a.recipient]
        if a.vault_cmd == "encrypt":
            vault.encrypt(a.source, a.out, rec, signer())
            print(f"encrypted {a.source} -> {a.out} for {len(rec)} recipient(s)")
        else:
            target, pruned = vault.backup(a.source, a.to, rec, signer(), a.keep)
            print(f"backup {target}" + (f"; removed {len(pruned)} old" if pruned else ""))
    elif a.vault_cmd == "decrypt":
        target, who = vault.decrypt(a.file, a.out, vault.Identity.load(a.key, passphrase()), a.ca, a.crl, a.signer, a.require_signature)
        print(f"restored {target}" + (f", signed by {who}" if who else ", not signed"))
    elif a.vault_cmd == "share":
        n = vault.add_recipients(a.file, vault.Identity.load(a.key, passphrase()), [vault.Recipient.load(r) for r in a.recipient])
        print(f"{a.file} now opens for {n} recipient(s); the encrypted data was not rewritten")
    elif a.vault_cmd == "inspect":
        show(vault.inspect(a.file), a.json)
    return 0


def cmd_bundle(a):
    from .bundles import create
    out = create(a.service, a.out or f"{a.service}-pqc", a.host, a.ca, a.mtls, a.policy)
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
    s.backups += a.backups
    app = App(s)
    httpd = serve(app)
    host, port = httpd.server_address[:2]
    print(f"console on http://{host}:{port}/  access token: {app.token}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print("warning: listening beyond localhost over plain HTTP; put `pqcsuite edge --policy transition` in front of it")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    stop = threading.Event()
    run_until_signal(stop.wait, lambda: (httpd.shutdown(), stop.set()))
    return 0


def cmd_enroll(a):
    from . import est
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
    print(f"renew it daily from cron: pqcsuite enroll {a.url} --renew {a.out} --within-days 30")
    return 0


def serve_json(address, routes):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
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
    from .edge import hostport
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
        return json.dumps({"time": self.formatTime(r), "level": r.levelname, "logger": r.name, "message": r.getMessage()})


def tls_client_args(p):
    p.add_argument("target", help="host:port")
    p.add_argument("--server-name", help="name the certificate must match (default: host)")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Post-quantum secure communication: certificate authority, TLS 1.3, edge proxy.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check that this machine can run everything")

    ca = sub.add_parser("ca", help="post-quantum certificate authority").add_subparsers(dest="ca_cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default="pki", help="CA folder (default: pki)")
    p = ca.add_parser("init", parents=[common], help="create a root CA")
    p.add_argument("--name", required=True)
    p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-87")
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
        p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65")
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
    p = ca.add_parser("token", parents=[common], help="one-time enrollment token for one name (for `pqcsuite enroll`)")
    p.add_argument("kind", choices=["server", "client", "site"])
    p.add_argument("common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--hours", type=float, default=24)
    p = ca.add_parser("serve", parents=[common], help="EST enrollment service (RFC 7030) over post-quantum TLS")
    p.add_argument("--listen", default="0.0.0.0:9443")
    p.add_argument("--cert", required=True, help="the service's own server chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    p = ca.add_parser("maintain", parents=[common], help="renew what expires soon and refresh the CRL (run daily)")
    p.add_argument("--renew-within", type=int, default=30, metavar="DAYS")
    p.add_argument("--crl-days", type=int, default=7)
    p = ca.add_parser("list", parents=[common], help="list issued certificates")
    p.add_argument("--expiring", type=int, metavar="DAYS", help="only those expiring within DAYS")
    p.add_argument("--json", action="store_true")

    t = sub.add_parser("tls", help="PQC TLS 1.3 server, client and probe").add_subparsers(dest="tls_cmd", required=True)
    p = t.add_parser("serve", help="an echo server, for testing clients")
    p.add_argument("--listen", default="0.0.0.0:8443")
    p.add_argument("--cert", required=True, help="chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    p.add_argument("--ca", help="CA that signs client certificates")
    p.add_argument("--require-client-cert", action="store_true", help="mutual TLS")
    p.add_argument("--crl", help="refuse revoked client certificates")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    p = t.add_parser("connect", help="handshake, optionally send a message, print what was negotiated")
    tls_client_args(p)
    p.add_argument("--ca", required=True)
    p.add_argument("--cert", help="client certificate, for mutual TLS")
    p.add_argument("--key")
    p.add_argument("--key-passphrase-env")
    p.add_argument("--send", help="message to send; the reply is printed")
    p = t.add_parser("probe", help="which post-quantum groups does a server accept?")
    tls_client_args(p)

    e = sub.add_parser("edge", help="PQC TLS in front of any TCP service, or a tunnel to one")
    e.add_argument("--config", help="TOML file with [[edge]] routes; replaces the flags below")
    e.add_argument("--mode", choices=["terminate", "originate"], default="terminate")
    e.add_argument("--listen", default="0.0.0.0:8443")
    e.add_argument("--target", help="upstream host:port (terminate) or remote edge host:port (originate)")
    e.add_argument("--policy", choices=list(tls.POLICIES), default="strict")
    for flag in ("--cert", "--key", "--key-passphrase-env", "--ca", "--crl", "--server-name", "--metrics"):
        e.add_argument(flag)
    e.add_argument("--require-client-cert", action="store_true")
    e.add_argument("--proxy-protocol", action="store_true", help="send a PROXY v1 header so the upstream sees the client address")

    q = sub.add_parser("vault", help="quantum-safe encryption for files, folders and backups").add_subparsers(dest="vault_cmd", required=True)
    p = q.add_parser("keygen", help="a recipient key pair (ML-KEM-768 + X25519)")
    p.add_argument("out", help="writes OUT.key and OUT.pub")
    p.add_argument("--passphrase-env")
    p.add_argument("--no-passphrase", action="store_true")
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
    p.add_argument("-o", "--out", default=".")
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

    p = sub.add_parser("scan", help="post-quantum readiness report for many TLS endpoints")
    p.add_argument("targets", nargs="+", help="host:port entries, or .txt files with one per line")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument("--json", help="write JSON results")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--timeout", type=float, default=8.0)

    p = sub.add_parser("console", help="web dashboard for certificates, edges, VPN, backups and readiness")
    p.add_argument("--config", help="TOML with a [console] section")
    p.add_argument("--listen", help="default 127.0.0.1:8900")
    p.add_argument("--ca", help="CA folder")
    p.add_argument("--edge", action="append", default=[], help="an edge's metrics address, e.g. http://127.0.0.1:9100 (repeatable)")
    p.add_argument("--vici", action="append", default=[], help="strongSwan VICI address (repeatable)")
    p.add_argument("--backups", action="append", default=[], help="folder of vault archives (repeatable)")

    p = sub.add_parser("enroll", help="get or renew a certificate from an EST enrollment service; the key stays on this machine")
    p.add_argument("url", help="https://ca.example.com:9443")
    p.add_argument("--token", help="one-time token from `pqcsuite ca token`")
    p.add_argument("--cn", dest="common_name")
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--out", default=".")
    p.add_argument("--ca", help="trusted CA certificate")
    p.add_argument("--ca-fingerprint", help="or the CA's SHA-256 fingerprint, to download and pin it")
    p.add_argument("--renew", metavar="FOLDER", help="renew the certificate in FOLDER in place")
    p.add_argument("--within-days", type=int, help="with --renew: only when it expires within this many days")
    p.add_argument("--server-name")
    p.add_argument("--key-passphrase-env")

    from .bundles import SERVICES
    p = sub.add_parser("bundle", help="a PQCready service: nginx, postgres, pgvector or mqtt behind the PQC edge")
    p.add_argument("service", choices=list(SERVICES))
    p.add_argument("--host", required=True, help="the name clients use; goes in the certificate")
    p.add_argument("--out", help="folder to create (default: SERVICE-pqc)")
    p.add_argument("--ca", help="use this existing CA folder instead of creating one")
    p.add_argument("--mtls", action="store_true", help="clients must present a certificate from the CA")
    p.add_argument("--policy", choices=list(tls.POLICIES), default="strict")

    v = sub.add_parser("vpn", help="post-quantum site-to-site IPsec (strongSwan)").add_subparsers(dest="vpn_cmd", required=True)
    p = v.add_parser("up", help="run a site: key agreement, rotation, revocation, metrics")
    p.add_argument("--config", required=True, help="site TOML (see examples/vpn-hq.toml)")
    for name, text in (("status", "tunnels, algorithms and traffic"), ("check", "is strongSwan reachable and does it have ML-KEM?")):
        p = v.add_parser(name, help=text)
        p.add_argument("--config", help="read the VICI address from a site TOML")
        p.add_argument("--vici", default="unix:///var/run/charon.vici")
        p.add_argument("--json", action="store_true")
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter() if a.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, handlers=[h])
    if a.cmd == "edge" and not a.config and not a.target:
        parser().error("edge needs --config or --target")
    try:
        sys.exit({"doctor": cmd_doctor, "ca": cmd_ca, "tls": cmd_tls, "edge": cmd_edge, "vpn": cmd_vpn, "vault": cmd_vault, "bundle": cmd_bundle, "scan": cmd_scan, "console": cmd_console, "enroll": cmd_enroll}[a.cmd](a))
    except (CAError, CharonError, VaultError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
