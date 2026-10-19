"""The certificate authority the VPN needs: gateways, sites and people get ML-DSA certificates from it, invitations enroll
against its EST service, and its revocation list cuts tunnels."""
import json
import os
from pathlib import Path

from acxelin_core.cli import ask, positive, run_until_signal
from acxelin_core.config import env_passphrase
from acxelin_core.pki import ALGORITHMS, CA, CA_ALGORITHMS, REASONS, CAError, encrypted

from . import legacy

CA_PASS_ENV = "ACXELIN_VPN_CA_PASSPHRASE"


def ca_passphrase(root, new=False):
    """From ACXELIN_VPN_CA_PASSPHRASE (or the suite's PQCSUITE_CA_PASSPHRASE) or a prompt, only when the key is or will be encrypted."""
    if not new and not encrypted(Path(root) / "ca.key"):
        return None
    given = os.environ.get(CA_PASS_ENV)
    if not given and (given := os.environ.get("PQCSUITE_CA_PASSPHRASE")):
        legacy.warn("PQCSUITE_CA_PASSPHRASE", CA_PASS_ENV)
    if given:
        return given.encode()
    if not new:
        return ask("CA passphrase: ", f"set {CA_PASS_ENV}")
    instead = f"set {CA_PASS_ENV}, or pass --no-encrypt to leave the CA key unencrypted"
    p1, p2 = ask("New CA passphrase: ", instead), ask("Repeat: ", instead)
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1


def cmd_ca(a):
    if a.ca_cmd == "init":
        ca = CA.init(a.dir, a.name, a.algorithm, a.days, None if a.no_encrypt else ca_passphrase(a.dir, new=True))
        print(f"created {ca.algorithm} root '{a.name}' in {a.dir}; gateways and people trust {ca.anchor}, gateways check {Path(a.dir) / 'crl.pem'}\n"
              f"next: acxelin-vpn ca issue site GATEWAY-NAME --san ADDRESS --dir {a.dir}")
        return 0
    ca = CA(a.dir, None if a.ca_cmd == "list" else ca_passphrase(a.dir))
    if a.ca_cmd == "issue":
        out, r = ca.issue(a.common_name, a.kind, a.san, a.days, a.algorithm, a.out, env_passphrase(a.key_passphrase_env))
        print(f"issued {r.kind} certificate {r.serial} for {r.common_name} ({r.algorithm}), valid until {r.not_after}")
        print(f"  {out / 'cert.pem'}\n  {out / 'chain.pem'}  (certificate + CA: what a gateway presents)\n  {out / 'key.pem'}")
    elif a.ca_cmd == "revoke":
        ca.revoke(a.serial, a.reason)
        print(f"revoked {ca.find(a.serial).serial}; {Path(a.dir) / 'crl.pem'} updated. Gateways following it with crl_url cut the "
              f"tunnel within a minute; copy it to any others")
    elif a.ca_cmd == "crl":
        ca.crl(a.days)
        print(f"wrote {Path(a.dir) / 'crl.pem'}")
    elif a.ca_cmd == "serve":
        from cryptography.x509 import load_pem_x509_certificate
        from acxelin_core.pki.est import fingerprint, serve
        srv = serve(a.dir, a.listen, a.cert, a.key, ca_passphrase(a.dir), env_passphrase(a.key_passphrase_env))
        print(f"EST enrollment on https://{a.listen}/.well-known/est for `acxelin-vpn invite --enroll`; CA fingerprint:\n"
              f"{fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes()))}")
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


def add(sub, common):
    ca = sub.add_parser("ca", help="the certificate authority for gateways, sites and people (ML-DSA), and its enrollment service").add_subparsers(dest="ca_cmd", required=True)
    p = ca.add_parser("init", parents=[common], help="create the VPN's certificate authority",
                      epilog='example: acxelin-vpn ca init --name "Example VPN Root" --dir pki')
    p.add_argument("--name", required=True, help="the CA's name, shown in every certificate it issues")
    p.add_argument("--algorithm", choices=CA_ALGORITHMS, default="ML-DSA-87", help="SLH-DSA keys need OpenSSL 3.5+")
    p.add_argument("--days", type=int, default=3650, help="the CA certificate's lifetime (default: 3650, ten years)")
    p.add_argument("--no-encrypt", action="store_true",
                   help=f"leave the CA key unencrypted (by default it is encrypted, passphrase from {CA_PASS_ENV} or a prompt)")
    p = ca.add_parser("issue", parents=[common], help="issue a key and certificate for a gateway, a site or a person",
                      epilog="example: acxelin-vpn ca issue site hq.example --san 198.51.100.1 --dir pki --out hq")
    p.add_argument("kind", choices=["site", "server", "client"], help="site: an IPsec gateway (both ends); server: the WireGuard gateway; client: a person")
    p.add_argument("common_name", help="the gateway, site or person it certifies")
    p.add_argument("--san", action="append", default=[], help="DNS name or IP (repeatable)")
    p.add_argument("--algorithm", choices=list(ALGORITHMS), default="ML-DSA-65")
    p.add_argument("--days", type=int, default=397)
    p.add_argument("--out", help="folder for cert.pem, chain.pem and key.pem")
    p.add_argument("--key-passphrase-env", help="encrypt the new key with the passphrase in this environment variable")
    p = ca.add_parser("revoke", parents=[common], help="revoke a certificate: its tunnels are cut and it gets no new keys")
    p.add_argument("serial")
    p.add_argument("--reason", default="unspecified", choices=["unspecified", *REASONS],
                   help="recorded in the CRL; keyCompromise when the key was stolen or exposed")
    p = ca.add_parser("crl", parents=[common], help="re-sign the revocation list (do this before it expires)")
    p.add_argument("--days", type=positive(int), default=7, help="how long the CRL is valid (default: 7)")
    p = ca.add_parser("maintain", parents=[common], help="renew what expires soon and re-sign the revocation list (run daily)")
    p.add_argument("--renew-within", type=int, default=30, metavar="DAYS", help="renew certificates expiring within DAYS (default: 30)")
    p.add_argument("--crl-days", type=positive(int), default=7, help="how long the re-signed CRL is valid (default: 7 days)")
    p = ca.add_parser("list", parents=[common], help="list issued certificates")
    p.add_argument("--expiring", type=int, metavar="DAYS", help="only those expiring within DAYS")
    p.add_argument("--json", action="store_true")
    p = ca.add_parser("serve", parents=[common], help="the enrollment service invitations use (EST, RFC 7030, over post-quantum TLS)")
    p.add_argument("--listen", default="0.0.0.0:9443", help="host:port (default: every interface, port 9443)")
    p.add_argument("--cert", required=True, help="the service's own server chain.pem")
    p.add_argument("--key", required=True)
    p.add_argument("--key-passphrase-env")
    for c in ca.choices.values():
        c.set_defaults(func=cmd_ca)
