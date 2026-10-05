"""Writes site/readiness-sample.html, the sample audit report the website links to, from real output of the suite run
against invented systems on this machine: a certificate authority, three TLS endpoints (post-quantum only, post-quantum
with a classical fallback, classical only), two Vault backups and the Wolf Pack example applications. Only the
endpoint addresses are renamed, from 127.0.0.1:PORT to example host names. Needs OpenSSL 3.5 (see pqcsuite doctor).

    python examples/readiness-sample/make_report.py
"""
import datetime as dt
import logging
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "wolf-pack")]
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from pqcsuite import vault  # noqa: E402
from pqcsuite.console import App, Settings  # noqa: E402
from pqcsuite.pki import CA  # noqa: E402
from pqcsuite.readiness import compliance, scan  # noqa: E402
from pqcsuite.tls.edge import Edge, Route  # noqa: E402
from wolfpack import cli as wolfpack  # noqa: E402

SYSTEMS = ["payments-api", "customer-portal", "batch-jobs"]
NOTICE = ('<p class=sample><b>Sample report.</b> Every system in it is invented and ran on one test machine; the findings are the '
          'suite\'s real output for them. Your report lists your own certificates, endpoints, tunnels, backups and code.</p>')


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def classical_cert(d, name, key):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))
    (d / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(d / f"{name}.crt"), str(d / f"{name}.key")


def classical_server(cert, key):
    """A server that predates post-quantum TLS: TLS 1.2 with an RSA certificate, as many payment switches still are."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    logging.disable(logging.WARNING)  # the scanner's deliberate classical probes are refused, as they should be
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        ca = CA.init(d / "pki", "Example Bank Root", passphrase=None)
        for kind, name in (("server", "api.examplebank.test"), ("server", "portal.examplebank.test"), ("client", "payments-batch"), ("client", "branch-042")):
            ca.issue(name, kind, out=d / name)
        ca.crl()
        web = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        target = f"127.0.0.1:{web.server_address[1]}"
        fallback = classical_cert(d, "portal-fallback", ec.generate_private_key(ec.SECP256R1()))
        edges = [Edge(Route("api", "terminate", "127.0.0.1:0", target, cert=str(d / "api.examplebank.test" / "chain.pem"),
                            key=str(d / "api.examplebank.test" / "key.pem"))).start(),
                 Edge(Route("portal", "terminate", "127.0.0.1:0", target, policy="transition", cert=str(d / "portal.examplebank.test" / "chain.pem"),
                            key=str(d / "portal.examplebank.test" / "key.pem"), fallback_cert=fallback[0], fallback_key=fallback[1])).start()]
        legacy = classical_server(*classical_cert(d, "switch", rsa.generate_private_key(public_exponent=65537, key_size=2048)))
        names = {f"127.0.0.1:{edges[0].port}": "api.examplebank.test:443", f"127.0.0.1:{edges[1].port}": "portal.examplebank.test:443",
                 f"127.0.0.1:{legacy.server_address[1]}": "payments-switch.examplebank.test:443"}
        try:
            results = scan.scan(list(names), timeout=10)
        finally:
            for edge in edges:
                edge.stop(0)
            legacy.shutdown()
            web.shutdown()
        for r in results:
            r["target"] = names[r["target"]]
        backups = d / "backups"
        backups.mkdir()
        ops, recovery = vault.Identity.generate(), vault.Identity.generate()
        for name in ("ledger-2026-10-04", "statements-2026-10-05"):
            (d / f"{name}.csv").write_text("date,amount\n2026-10-01,1200\n")
            vault.encrypt(d / f"{name}.csv", backups / f"{name}.pqv", [ops.public, recovery.public])
        rows = compliance.certificates(App(Settings(ca=str(d / "pki"))).ca().records()) + compliance.endpoints(results)
        rows += compliance.backups(App(Settings(backups=[str(backups)])).backups())
        for system in SYSTEMS:
            out = d / "wolfpack" / system
            if wolfpack.main(["scan", str(ROOT / "examples" / "wolfpack-sample" / system), "-o", str(out), "-q"]) not in (0, 2):
                raise SystemExit(f"Wolf Pack could not scan {system}")
            rows += compliance.code(out)
        page = compliance.to_html(compliance.report(rows), title="Example Bank: post-quantum readiness")
        page = page.replace("<div class=tiles>", NOTICE + "<div class=tiles>", 1).replace(
            "</style>", ".sample{margin:0 0 18px;padding:12px 16px;border-radius:10px;background:var(--accent-wash);border:1px solid var(--line)}</style>", 1)
        (ROOT / "site" / "readiness-sample.html").write_text(page, encoding="utf-8")
    print("wrote site/readiness-sample.html")


if __name__ == "__main__":
    main()
